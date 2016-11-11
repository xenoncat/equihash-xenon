#!/usr/bin/env python3

"""
Z-Cash Equihash Miner

Equihash solver by Xenoncat
Stratum mining framework by Joris van Rantwijk

Usage: equimine.py {options}

Options:
    -l host.name.org:port   Host and TCP port of Stratum server
    -u username             Username for Stratum server (or z-cash address)
    -p password             Password for Stratum server (default: 'x')
    -t num_threads          Number of CPU threads (default: 1)
    -b num_iter             Run benchmark with specified number of iterations
    -d                      Show debug messages
    --hugetlb               Force use of huge pages (default: autodetect)
    --no-hugetlb            Do not use huge pages

"""

import sys
import argparse
import asyncio
import collections
import hashlib
import json
import logging
import math
import multiprocessing
import os
import os.path
import socket
import struct
import time

# Import the extension module.
try:
    import equihash_xenoncat
except ImportError:
    # Importing failed. Perhaps the extension was built but not yet installed.
    import distutils.util
    sys.path.append(os.path.join('build', 'lib.' +
                                 distutils.util.get_platform() + '-' +
                                 sys.version[:3]))
    import equihash_xenoncat


############################################################
# Utility functions
############################################################

def HexToBytes(h):
    """Convert hex string to bytes object."""

    if len(h) % 2 != 0:
        raise ValueError('Invalid hex string length %d (expecting even length)'
                         % len(h))
    return bytes([ int(h[i:i+2], 16) for i in range(0, len(h), 2) ])


def BytesToHex(b):
    """Convert bytes to hex string."""

    return ''.join([ ('%02x' % t) for t in b ])


def HexToLeU32(h):
    """Convert hex string to 4-byte little-endian unsigned integer."""

    if len(h) != 8:
        raise ValueError('Got hex string length %d (expecting length 8)'
                         % len(h))
    b = bytes([ int(h[i:i+2], 16) for i in range(0, 8, 2) ])
    return struct.unpack('<I', b)[0]


############################################################
# Worker threads
############################################################

# Workaround for multiprocessing issues.
all_parent_connections = [ ]


class Worker:
    """Running inside worker process."""

    SOLPREFIX = struct.pack('<BH', 253, 1344)

    def __init__(self, taskid, conn, hugetlb):

        self.log     = logging.getLogger('w%d' % taskid)
        self.taskid  = taskid
        self.conn    = conn
        self.itercnt = 0
        self.solcnt  = 0
        self.job     = None
        self.target  = None
        self.noncebase = None
        self.nonceval  = None
        self.closing = False

        self.log.debug('Initializing Equihash engine')
        self.xenon = equihash_xenoncat.EquihashXenoncat(hugetlb=hugetlb)
        self.log.debug('using avxversion=%d hugetlb=%d',
                       self.xenon.avxversion, self.xenon.hugetlb)

    def run(self):

        self.log.debug('Starting worker %d', self.taskid)

        while not self.closing:

            self.handleMessages()
            if self.closing:
                break

            if self.job is not None:
                self.solverun()
                self.stats()

        self.log.debug('Stopping worker %d', self.taskid)

        self.conn.close()
        self.conn = None

    def handleMessages(self):

        while not self.closing:

            if self.job is None:
                # Nothing to do, wait for message.
                timeout = 2.0
            else:
                # Job in progress, only read received messages.
                timeout = 0.0

            try:
                if not self.conn.poll(timeout):
                    break
                msg = self.conn.recv()
            except (EOFError, OSError) as e:
                self.log.error('Lost connection to main process')
                self.closing = True
                break

            if msg[0] == 'close':
                self.closing = True

            elif msg[0] == 'pause':
                self.job = None
                self.log.debug('Pausing worker %d', self.taskid)

            elif msg[0] == 'job':
                self.startJob(JobStruct(*msg[1]), msg[2], msg[3])

    def _sendMsg(self, msg):
        """Send message to main process."""

        try:
            self.conn.send(msg)
        except OSError:
            # Ignore send errors. If connection to main process is lost,
            # we will discover it when trying to read.
            self.log.error('Can not send message to main process')

    def submit(self, nonce2, solution):
        """Submit solution to main process."""

        msg = ('submit', tuple(self.job), nonce2, solution)
        self._sendMsg(msg)

    def stats(self):
        """Send statistics to main process."""

        msg = ('stats', self.itercnt, self.solcnt)
        self._sendMsg(msg)

    def startJob(self, job, startnonce, target):

        self.log.debug('Worker %d starts job %r', self.taskid, job.jobid)

        self.job = job
        self.nonceval = startnonce
        self.target = target

        # Create random nonce bytes to fill up to required nonce length.
        assert len(job.nonce1) + 4 <= 32
        self.noncebase = b''
        if len(job.nonce1) + 4 < 32:
            self.noncebase = os.urandom(32 - 4 - len(job.nonce1))

    def checkSolution(self, nonce2, solution):
        """Check that specified solution is within difficulty target."""

        header = self.job.header + self.job.nonce1 + nonce2 + solution
        h1 = hashlib.sha256(header).digest()
        h2 = hashlib.sha256(h1).digest()

        # NOTE: Must read SHA256 hash digest in reserve byte order.
        h = h2[::-1]

        return h <= self.target

    def solverun(self):
        """Run one iteration of the solver."""

        # Calculate full nonce2 data.
        nonce2 = self.noncebase + struct.pack('<I', self.nonceval)

        self.log.debug('Run equihash solver')

        # Prepare Equihash engine for input data.
        inputdata = self.job.header + self.job.nonce1 + self.noncebase
        assert len(inputdata) == 136
        self.xenon.prepare(inputdata)

        # Run Equihash solver.
        solutions = self.xenon.solve(self.nonceval)
        self.log.debug('found %d solutions', len(solutions))

        self.nonceval += 1
        self.itercnt  += 1
        self.solcnt   += len(solutions)

        # Submit solutions within target.
        for sol in solutions:

            # NOTE: The binary Equihash solution must be prefixed with
            # a 3-byte length marker before further processing.
            # I didn't know this and spent several hours figuring out why
            # all my solutions were invalid.
            bsol = self.SOLPREFIX + sol

            if self.checkSolution(nonce2, bsol):
                self.submit(nonce2, bsol)


class WorkerHandle:
    """Used by the main process to represent a worker process."""

    def __init__(self, eventloop, manager, taskid, hugetlb):
        """Create worker process."""

        self.log       = logging.getLogger('wh%d' % taskid)

        self.eventloop = eventloop
        self.manager   = manager
        self.taskid    = taskid

        self.itercnt   = 0
        self.solcnt    = 0

        # Create communication pipe.
        (conn1, conn2) = multiprocessing.Pipe(duplex=True)
        self.conn = conn1

        # NOTE: The multiprocessing module is fucked up to the point
        # that it is barely usable. Since all childs inherit all pipe
        # descriptors, all pipes remain open until all processes exit
        # therefore one crashing process causes deadlock on all other
        # processes. We hack our way through it by manually closing
        # descriptors.
        all_parent_connections.append(conn1)

        self.log.info('Creating worker %d' % taskid)

        # Create worker process and start.
        # Set the 'daemon' flag to True to make sure that the child will
        # be terminated when the main process ends, instead of the main
        # process deadlocking by waiting for the child to end.
        args = (taskid, conn2, hugetlb, list(all_parent_connections))
        self.proc = multiprocessing.Process(target=self._run,
                                            args=args,
                                            daemon=True)
        self.proc.start()

        # Close child end of pipe to work around multiprocessing issues.
        conn2.close()

        # Listen to messages from worker.
        eventloop.add_reader(self.conn, self._readyRead)

    def _sendMsg(self, msg):
        """Send message to worker process."""

        try:
            self.conn.send(msg)
        except OSError:
            # Ignore send errors. If connection to worker is lost,
            # we will discover it when trying to read.
            self.log.error('Can not send message to worker %d', self.taskid)

    def close(self):
        """Stop worker and clean up worker process."""

        self.log.info('Stopping worker %d' % self.taskid)

        # Send command to close worker.
        msg = ('close',)
        self._sendMsg(msg)
        self.conn.close()
        all_parent_connections.remove(self.conn)
        self.conn = None

        # Clean up worker process.
        self.proc.join()
        self.proc = None

        self.log.info('Worker %d cleaned up' % self.taskid)

    def pause(self):
        """Pause worker."""

        msg = ('pause',)
        self._sendMsg(msg)

    def startJob(self, job, startnonce, target):

        msg = ('job', tuple(job), startnonce, target)
        self._sendMsg(msg)

    def _readyRead(self):
        """Called when the worker process sends a message."""

        try:
            msg = self.conn.recv()
        except (EOFError, OSError) as e:
            # This happens if the worker fails to initialize or if
            # it crashes. There is no sensible way to continue at this
            # point, so stop the miner.
            self.log.error('Lost connection to worker %d', self.taskid)
            self.manager.terminate()
            return

        if msg[0] == 'submit':
            job      = JobStruct(*msg[1])
            nonce2   = msg[2]
            solution = msg[3]
            self.manager.submit(job, nonce2, solution)

        elif msg[0] == 'stats':
            self.itercnt = msg[1]
            self.solcnt  = msg[2]
            if self.manager.benchmarking:
                self.manager.statsUpdated()

        else:
            self.log.error("Invalid message from workes %d (%r)",
                           self.taskid, msg)
            self.manager.terminate()

    @staticmethod
    def _run(taskid, conn, hugetlb, must_close_connections):
        """Main function inside worker process."""

        # Close parent side of pipes to work around multiprocessing issues.
        for c in must_close_connections:
            c.close()

        try:
            worker = Worker(taskid, conn, hugetlb)
            worker.run()
        except KeyboardInterrupt:
            print("Worker %d exit on Ctrl-C" % taskid, file=sys.stderr)


############################################################
# Stratum client
############################################################

JobStruct = collections.namedtuple('JobStruct', 'jobid header ntime nonce1')


class StratumClient:
    """Client for Stratum mining pool."""

    TIMEOUT = 30.0

    def __init__(self, eventloop, manager, host, port, username, password):

        self.log        = logging.getLogger('stratum')
        self.eventloop  = eventloop
        self.manager    = manager
        self.host       = host
        self.port       = port
        self.username   = username
        self.password   = password
        self.conn       = None
        self.job        = None
        self.nonce1     = None
        self.target     = None
        self.submitcnt  = 0
        self.sharecnt   = 0
        self.sharescore = 0.0
        self.reqid      = 0
        self.inbuf      = b''
        self.pendingCompletion = { }

    def connect(self):
        """(Re-)connect to the pool.

        This function blocks until the TCP connection is established.
        This function raises OSError if the TCP connection fails.
        """

        if self.conn is not None:
            self.log.info('Closing connection to pool')
            self.close()

        self.log.info('Connecting to pool %s:%d', self.host, self.port)

        self.conn = socket.create_connection((self.host, self.port),
                                             timeout=self.TIMEOUT)

        self.eventloop.add_reader(self.conn, self._readyRead)

        self.log.info('Subscribing to pool')

        self.sendRequest(method="mining.subscribe",
                         params=[],
                         completion=self._subscribed)

    def close(self):
        """Close connection to pool."""

        self.job    = None
        self.nonce1 = None
        self.target = None
        self.inbuf  = b''
        self.pendingCompletion = { }

        # Note: Some Stratum pool implementations are so fucked up that
        # they require the client to start with id=1 for the first request
        # on each connection.
        self.reqid      = 0

        if self.conn is not None:
            self.eventloop.remove_reader(self.conn)
            self.conn.close()
            self.conn = None

    def submit(self, job, nonce2, solution):
        """Submit solution to Stratum pool."""

        if self.conn is None:
            self.log.warning('Can not submit while not connected')
            return

        self.submitcnt += 1
        self.log.info('Submitting solution #%d', self.submitcnt)

        # Send RPC request.
        params = [ self.username,
                   job.jobid,
                   BytesToHex(job.ntime),
                   BytesToHex(nonce2),
                   BytesToHex(solution) ]

        completion = lambda r, e: self._submitted(self.submitcnt, r, e)
        self.sendRequest(method="mining.submit",
                         params=params,
                         completion=completion)

    def sendRequest(self, method, params, completion):
        """Send JSON request to pool and register completion handler."""

        assert self.conn is not None

        # Make JSON request.
        self.reqid += 1
        reqobj = { 'id': self.reqid, 'method': method, 'params': params }
        reqstr = json.dumps(reqobj)

        # Register completion handler.
        self.pendingCompletion[self.reqid] = completion

        # Send request to server.
        self.log.debug("sending: '%s'", reqstr)
        try:
            self.conn.settimeout(self.TIMEOUT)
            self.conn.send(reqstr.encode() + b'\n')
        except OSError as e:
            self.log.error(str(type(e)) + ': ' + str(e))
            self.close()
            self.manager.poolConnectionDown()

    def _subscribed(self, result, err):
        """Called when the pool answers our subscribe request."""

        self.log.debug("mining.subscribe result=%r", result)

        # The meaning of mining.subscribed result is unclear.
        # Many Stratum specs say that result[1] is extranonce1.
        # However Slush says for Zcash mining result[0] is extranonce1
        # and result[1] is the session ID.
        # We bet on result[1], it seems to work with most pools.

        try:
            if len(result) < 2:
                raise ValueError('Invalid subscription result (need 2 values)')
            self.nonce1 = HexToBytes(result[1])
            if len(self.nonce1) > 28:
                raise ValueError('Got nonce1 length %d (maximum is 28)' %
                                 len(self.nonce1))
        except (TypeError, ValueError) as e:
            self.log.error(str(type(e)) + ': ' + str(e))
            self.log.error('mining.subscribe result=%r, error=%r', result, err)
            self.close()
            self.manager.poolConnectionDown()
            return

        self.log.info('Subscribed to pool nonce1=%s', BytesToHex(self.nonce1))

        self.log.info('Authenticating to pool')

        self.sendRequest(method="mining.authorize",
                         params=[ self.username, self.password ],
                         completion=self._authorized)

    def _authorized(self, result, err):
        """Called when the pool answers our authorize request."""

        if result:
            self.log.info("Authenticated to pool")
            self.manager.poolConnectionUp()
        else:
            self.log.error("Authentication to pool failed")
            self.log.error('mining.authorize result=%r error=%r', result, err)
            self.close()
            self.manager.poolConnectionDown()

    def _submitted(self, submitcnt, result, err):
        """Called when the pool answers a submit request."""

        if result:
            self.log.info("Solution #%d accepted", submitcnt)
            self.sharecnt += 1
            self.sharescore += 1.0 / sum([ self.target[i] / 256.0**(i+1)
                                           for i in range(8) ])
        else:
            self.log.info("Solution #%d rejected (%r)", submitcnt, err)

    def _readyRead(self):
        """Called by the event loop when we receive data from the pool."""

        assert self.conn is not None

        # NOTE: Connection may be closed from inside this loop.
        while self.conn is not None:

            # Non-blocking read from socket.
            try:
                # NOTE: It may seem like we could use MSG_DONTWAIT here
                # to avoid constantly changing the timeout/blocking mode
                # of the socket. WRONG!!
                # The fucking Python library silently ignores MSG_DONTWAIT
                # when a timeout has been set for the socket.
                self.conn.setblocking(False)
                s = self.conn.recv(4096)
            except (BlockingIOError, socket.timeout):
                # No more data available.
                break

            if not s:
                # Socket closed by server.
                self.log.warning('Connection closed by pool')
                self.close()
                self.manager.poolConnectionDown()
                return

            self.inbuf += s

            if self.inbuf.find(b'\n') >= 0:
                break

        # Decode messages from server.
        while True:

            p = self.inbuf.find(b'\n')
            if p < 0:
                break

            msgstr = self.inbuf[:p].decode(errors='replace')
            self.inbuf = self.inbuf[p+1:]
            self.log.debug("receved: '%s'", msgstr)

            msg = None
            try:
                msg = json.loads(msgstr)
            except ValueError as e:
                # Report invalid message, then ignore it.
                self.log.error(str(type(e)) + ': ' + str(e))

            if msg is not None:
                self._handleMessage(msg)

    def _handleMessage(self, msg):
        """Handle a JSON message from the pool."""

        try:
            err    = msg.get('error')
            reqid  = msg.get('id')
            result = msg.get('result')
            have_result = ('result' in msg)
        except (TypeError, AttributeError) as e:
            self.log.error('Invalid RPC message %r', msg)
            return
            
        if err:
            self.log.error("RPC error %r", err)

        if reqid is not None and have_result:
            # This is an answer to a request from us.
            if reqid in self.pendingCompletion:
                completion = self.pendingCompletion[reqid]
                del self.pendingCompletion[reqid]
                completion(result, err)
            else:
                self.log.error('Got answer to unknown request id %r', reqid)

        else:
            # Otherwise, this must be a JSON call to us.
            self._handleRpc(msg)

    def _handleRpc(self, rpcobj):
        """Called when the pool sends us an RPC request."""

        try:
            method = rpcobj['method']
            params = rpcobj['params']
        except (TypeError, KeyError) as e:
            self.log.error('Invalid RPC request message %r', rpcobj)
            return

        if method == 'mining.notify':
            try:
                if len(params) < 8:
                    raise ValueError('Invalid job parameters (need 8 values)')
                jobid       = params[0]
                version     = HexToLeU32(params[1])
                if version != 4:
                    raise ValueError('Invalid job version (need version 4)')
                bversion    = HexToBytes(params[1])
                bprevhash   = HexToBytes(params[2])
                bmerkleroot = HexToBytes(params[3])
                breserved   = HexToBytes(params[4])
                bntime      = HexToBytes(params[5])
                ntime       = HexToLeU32(params[5])
                bbits       = HexToBytes(params[6])
                cleanjobs   = bool(params[7])
                if len(bversion) != 4:
                    raise ValueError('Got job version len %d (expecting 4)' %
                                     len(bversion))
                if len(bprevhash) != 32:
                    raise ValueError('Got job prevhash len %d (expecting 32)' %
                                     len(bprevhash))
                if len(bmerkleroot) != 32:
                    raise ValueError('Got job merkleroot len %d (expecting 32)'
                                     % len(bmerkleroot))
                if len(breserved) != 32:
                    raise ValueError('Got job reserved len %d (expecting 32)' %
                                     len(breserved))
                if len(bntime) != 4:
                    raise ValueError('Got job ntime len %d (expecting 4)' %
                                     len(bntime))
                if len(bbits) != 4:
                    raise ValueError('Got job bits len %d (expecting 4)' %
                                     len(bbits))
            except (TypeError, ValueError) as e:
                self.log.error(str(type(e)) + ': ' + str(e))
                self.log.error('mining.notify params=%r', params)
                return
            dtime = ntime - time.time()
            self.log.info("New job id=%s, dtime=%.1f", jobid, dtime)
            header = ( bversion + bprevhash + bmerkleroot + breserved +
                       bntime + bbits )
            self.job = JobStruct(jobid, header, bntime, self.nonce1)
            self.manager.jobChanged(self.job)

        elif method == 'mining.set_target':
            try:
                if len(params) < 1:
                    raise ValueError('Invalid target parameters')
                target = HexToBytes(params[0])
                if len(target) != 32:
                    raise ValueError('Got target len %d (expecting 32)' %
                                     len(target))
            except (TypeError, ValueError) as e:
                self.log.error('Bad parameters for mining.set_target %r',
                               params)
                return
            self.log.info('Target changed to ' + BytesToHex(target))
            if target != self.target:
                self.target = target
                self.manager.targetChanged(self.target)

        else:
            self.log.error("Unknown RPC method %r from server", method)


############################################################
# Mining manager
############################################################

class AverageStat:
    """Keep track of filtered average statistic over time."""

    def __init__(self, timeconst):

        self.timeconst = timeconst
        self.ptime = None
        self.pval  = None
        self.rate  = None

    def update(self, ntime, nval):

        if self.ptime is not None and ntime > self.ptime:
            dtime = ntime - self.ptime
            dval  = nval  - self.pval
            nrate = dval / float(dtime)
            if self.rate is None:
                self.rate = nrate
            else:
                k = math.exp(- dtime * (1.0 / self.timeconst))
                self.rate = k * self.rate + (1.0 - k) * nrate

        self.pval  = nval
        self.ptime = ntime


class MiningManager:
    """Manages the flow of information between Stratum pool and workers."""

    RECONNECT_INTERVAL  = 10.0
    SHOW_STATS_INTERVAL = 10.0
    STATS_TIMECONST     = 600.0  # 10 minutes

    def __init__(self, eventloop):

        self.log = logging.getLogger('manager')
        self.eventloop = eventloop
        self.pool = None
        self.workers = [ ]
        self.firstconnection = True
        self.exitcode = 0
        self.benchmarking = False

        self.avg_iter_rate  = AverageStat(self.STATS_TIMECONST)
        self.avg_solve_rate = AverageStat(self.STATS_TIMECONST)
        self.avg_share_rate = AverageStat(self.STATS_TIMECONST)
        self.avg_score_rate = AverageStat(self.STATS_TIMECONST)

    def setPool(self, pool):
        """Attach manager to a Stratum pool."""

        self.pool = pool

    def addWorker(self, wh):
        """Add a new WorkerHandle."""

        self.workers.append(wh)

    def poolConnectionUp(self):
        """Called when the connection to the Stratum pool is online."""

        if self.firstconnection:
            self.firstconnection = False
            t = time.monotonic()
            self.avg_iter_rate.update(t, 0)
            self.avg_solve_rate.update(t, 0)
            self.avg_share_rate.update(t, 0)
            self.avg_score_rate.update(t, 0)
            self.eventloop.call_later(self.SHOW_STATS_INTERVAL,
                                      self._showStats)

    def poolConnectionDown(self):
        """Called when the connection to the Stratum pool is lost."""

        if self.firstconnection:
            # First connection failed; just give up now.
            self.terminate()
            return

        # Pause all workers.
        for wh in self.workers:
            wh.pause()

        # Wait 10 seconds; then try to reconnect to the pool.
        self.eventloop.call_later(self.RECONNECT_INTERVAL, self.pool.connect)

    def targetChanged(self, newtarget):
        """Called when the Stratum pool sends a new target."""

        # Send new target to workers.
        if self.pool.job is not None:
            for (i, wh) in enumerate(self.workers):
                startnonce = i * (2**32 // len(self.workers))
                wh.startJob(self.pool.job, startnonce, newtarget)

    def jobChanged(self, newjob):
        """Called when the Stratum pool sends a new job."""

        # Send new job to workers.
        if self.pool.target is not None:
            for (i, wh) in enumerate(self.workers):
                startnonce = i * (2**32 // len(self.workers))
                wh.startJob(newjob, startnonce, self.pool.target)

    def submit(self, job, nonce2, solution):
        """Called when a worker finds a solution within target."""

        self.pool.submit(job, nonce2, solution)

    def terminate(self):
        """Terminate miner after fatal error."""

        self.log.warning('Terminating miner')
        self.exitcode = 1
        self.eventloop.stop()

    def _showStats(self):
        """Show statistics."""

        t = time.monotonic()

        totaliter  = sum([ wh.itercnt for wh in self.workers ])
        totalsolve = sum([ wh.solcnt  for wh in self.workers ])

        self.avg_iter_rate.update(t,  totaliter)
        self.avg_solve_rate.update(t, totalsolve)
        self.avg_share_rate.update(t, self.pool.sharecnt)
        self.avg_score_rate.update(t, self.pool.sharescore)

        iter_rate  = self.avg_iter_rate.rate
        solve_rate = self.avg_solve_rate.rate
        share_rate = self.avg_share_rate.rate
        score_rate = self.avg_score_rate.rate
        luck = 0 if iter_rate < 1.0e-8 else score_rate / (2.0 * iter_rate)

        self.log.info('%.3f run/s, %.3f Sol/s, %.3f share/hr (%d%% luck)',
                      iter_rate, solve_rate,
                      3600 * share_rate,
                      round(100 * luck))

        self.eventloop.call_later(self.SHOW_STATS_INTERVAL, self._showStats)


############################################################
# Benchmark
############################################################

# Test input.
beta1_block2 = bytes([
    0x04, 0x00, 0x00, 0x00, 0x91, 0x5f, 0xa6, 0x1c,
    0x4f, 0xa5, 0x92, 0x3c, 0xe6, 0xee, 0xad, 0x06,
    0x74, 0x6b, 0x61, 0x22, 0x54, 0x94, 0xea, 0x5a,
    0x2a, 0x97, 0xae, 0x46, 0x6e, 0x6f, 0xaa, 0x9c,
    0x6e, 0xf6, 0x3a, 0x0d, 0xa5, 0xfc, 0x67, 0xd7,
    0xf8, 0xdc, 0x78, 0xc3, 0xc8, 0x70, 0xca, 0x09,
    0xba, 0xab, 0xaa, 0xf7, 0x02, 0x59, 0x68, 0xa8,
    0x6f, 0xeb, 0x88, 0x75, 0xd3, 0xf3, 0xff, 0xa7,
    0x2e, 0xb0, 0x0f, 0x81, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x66, 0xce, 0xd2, 0x57,
    0x0f, 0x0f, 0x0f, 0x20, 0x00, 0x00, 0xf7, 0xf1,
    0x94, 0xa2, 0x53, 0x8e, 0x42, 0x5f, 0x21, 0x33,
    0xcf, 0xa8, 0xd3, 0xcb, 0xf4, 0xdf, 0x71, 0xef,
    0x38, 0x28, 0x51, 0x75, 0xcf, 0xed, 0xcb, 0x3e ])


class BenchmarkManager:
    """Benchmark driver, acting as a dummy mining manager."""

    def __init__(self, eventloop, niter):

        self.log = logging.getLogger('bench')
        self.eventloop = eventloop
        self.niter     = niter
        self.iterdone  = 0
        self.workers = [ ]
        self.exitcode = 0
        self.benchmarking = True

    def addWorker(self, wh):
        """Add a new WorkerHandle."""

        self.workers.append(wh)

    def start(self):
        """Start benchmark on all workers."""

        self.starttime = time.monotonic()

        header = beta1_block2[0:108]
        bntime = beta1_block2[100:104]
        nonce1 = beta1_block2[108:136]
        job = JobStruct('test', header, bntime, nonce1)

        target = bytes(32 * [ 0 ])

        for (i, wh) in enumerate(self.workers):
            startnonce = i * (2**32 // len(self.workers))
            wh.startJob(job, startnonce, target)

    def statsUpdated(self):
        """Called when worker completes an iteration."""

        duration = time.monotonic() - self.starttime
        self.iterdone += 1

        if self.iterdone == self.niter:

            totaliter = sum([ wh.itercnt for wh in self.workers ])
            totalsol  = sum([ wh.solcnt  for wh in self.workers ])

            iter_rate = totaliter / duration
            sol_rate  = totalsol / duration

            self.log.info('%d runs, %d solutions in %.3f seconds',
                          totaliter, totalsol, duration)
            self.log.info('%.3f run/s, %.3f Sol/s',
                          iter_rate, sol_rate)
            self.eventloop.stop()

        elif self.iterdone % 5 == 0:

            self.log.info('%d runs in %.3f seconds',
                          self.iterdone, duration)

    def submit(self, job, nonce, solution):
        pass

    def terminate(self):
        """Terminate miner after fatal error."""

        self.log.warning('Terminating miner')
        self.exitcode = 1
        self.eventloop.stop()


############################################################
# Main program
############################################################

def main():
    """Main program."""

    parser = argparse.ArgumentParser()

    parser.format_usage = lambda: __doc__
    parser.format_help  = lambda: __doc__

    parser.add_argument('-l', action='store', type=str,
        help='Host and TCP port of Stratum server')
    parser.add_argument('-u', action='store', type=str,
        help='Username for Stratum server (usually z-cash address)')
    parser.add_argument('-p', action='store', type=str, default='x',
        help="Password for Stratum server (default: 'x')")
    parser.add_argument('-t', action='store', type=int, default=1,
        help='Number of CPU threads (default: 1)')
    parser.add_argument('-b', action='store', type=int,
        help='Run benchmark with specifide number of iterations')
    parser.add_argument('-d', action='store_true',
        help='Show debug messages')
    parser.add_argument('--hugetlb', action='store_true',
        help='Allocate working memory in huge pages (default: autodetect)')
    parser.add_argument('--no-hugetlb', action='store_true',
        help='Do not allocate working memory in huge pages')

    args = parser.parse_args()

    if args.b is None:
        # Not running in benchmark mode; need host and username.

        if args.l is None:
            print(__doc__, file=sys.stderr)
            print("ERROR: Missing required argument -l", file=sys.stderr)
            sys.exit(1)

        if args.u is None:
            print(__doc__, file=sys.stderr)
            print("ERROR: Missing required argument -u", file=sys.stderr)
            sys.exit(1)

        w = args.l.split(':')
        if len(w) != 2:
            print(__doc__, file=sys.stderr)
            print("ERROR: Invalid -l argument, expecting 'host:port'",
                  file=sys.stderr)
            sys.exit(1)

        host = w[0]
        try:
            port = int(w[1])
        except ValueError:
            print(__doc__, file=sys.stderr)
            print("ERROR: Invalid -l argument, expecting 'host:port'",
                  file=sys.stderr)
            sys.exit(1)

    if args.t < 1 or args.t > 100:
        print(__doc__, file=sys.stderr)
        print("ERROR: Invalid -t argument, expecting value from 1 to 100",
              file=sys.stderr)
        sys.exit(1)

    if args.b is not None and args.b < 1:
        print(__doc__, file=sys.stderr)
        print("ERROR: Invalid -b argument, expecting positive value",
              file=sys.stderr)
        sys.exit(1)

    # Initialize logging.
    logging.basicConfig(
        format='%(asctime)s.%(msecs)03d %(name)-7s %(levelname)-5s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        level=logging.DEBUG if args.d else logging.INFO)

    # Create event loop.
    eventloop = asyncio.SelectorEventLoop()

    # Create mining manager.
    if args.b is not None:
        # Running in benchmark mode.
        manager = BenchmarkManager(eventloop, args.b)
    else:
        # Running in mining mode.
        manager = MiningManager(eventloop)

    # Create workers.
    hugetlb = 1 if args.hugetlb else (0 if args.no_hugetlb else -1)
    for i in range(args.t):
        wh = WorkerHandle(eventloop=eventloop,
                          manager=manager,
                          taskid=i+1,
                          hugetlb=hugetlb)
        manager.addWorker(wh)

    if args.b is not None:
        # Prepare to start benchmark.
        eventloop.call_soon(manager.start)

    else:
        # Running in mining mode.

        # Create stratum client.
        pool = StratumClient(eventloop=eventloop,
                             manager=manager,
                             host=host,
                             port=port,
                             username=args.u,
                             password=args.p)
        manager.setPool(pool)

        # Prepare to connect to pool.
        eventloop.call_soon(pool.connect)

    # Main loop.
    try:
        eventloop.run_forever()
    except KeyboardInterrupt:
        print("Exit on Ctrl-C", file=sys.stderr)

    sys.exit(manager.exitcode)


if __name__ == '__main__':
    main()

