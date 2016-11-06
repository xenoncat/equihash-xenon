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
# Exceptions
############################################################

class MinerError(Exception):
    """Raised in case of fatal error."""

    pass


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


# TODO : not needed ?
class SHA256_raw:

    _h0, _h1, _h2, _h3, _h4, _h5, _h6, _h7 = (
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)

    def handle(self, chunk):

        w = list(struct.unpack('>' + 16 * 'I', chunk))

        rrot = lambda x, n: (x >> n) | (x << (32 - n))

        k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

        for i in range(16, 64):
            s0 = rrot(w[i - 15], 7) ^ rrot(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = rrot(w[i - 2], 17) ^ rrot(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff)

        a = self._h0
        b = self._h1
        c = self._h2
        d = self._h3
        e = self._h4
        f = self._h5
        g = self._h6
        h = self._h7

        for i in range(64):
            s0 = rrot(a, 2) ^ rrot(a, 13) ^ rrot(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = s0 + maj
            s1 = rrot(e, 6) ^ rrot(e, 11) ^ rrot(e, 25)
            ch = (e & f) ^ ((~ e) & g)
            t1 = h + s1 + ch + k[i] + w[i]

            h = g
            g = f
            f = e
            e = (d + t1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xffffffff

        self._h0 = (self._h0 + a) & 0xffffffff
        self._h1 = (self._h1 + b) & 0xffffffff
        self._h2 = (self._h2 + c) & 0xffffffff
        self._h3 = (self._h3 + d) & 0xffffffff
        self._h4 = (self._h4 + e) & 0xffffffff
        self._h5 = (self._h5 + f) & 0xffffffff
        self._h6 = (self._h6 + g) & 0xffffffff
        self._h7 = (self._h7 + h) & 0xffffffff

    def digest(self):
        return struct.pack('>IIIIIIII',
          self._h0, self._h1, self._h2, self._h3,
          self._h4, self._h5, self._h6, self._h7)


############################################################
# Worker threads
############################################################

class Worker:
    """Running inside worker process."""

    def __init__(self, taskid, conn, hugetlb):

        self.log     = logging.getLogger('w%d' % taskid)
        self.taskid  = taskid
        self.conn    = conn
        self.itercnt = 0
        self.solcnt  = 0
        self.job     = None
        self.startnonce = None
        self.target  = None
        self.closing = False

        # TODO : init equihash engine

    def run(self):

        self.log.debug('Starting worker %d', self.taskid)

        while not self.closing:

            self.handleMessages()
            if self.closing:
                break

            if self.job is not None:
                self.solver()

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
            except EOFError as e:
                self.log.error('Lost connection to main process')
                self.closing = True
                break

            if msg[0] == 'close':
                self.closing = True

            elif msg[0] == 'pause':
                self.job = None
                self.log.debug('Pausing worker %d', self.taskid)

            elif msg[0] == 'job':
                self.job = JobStruct(*msg[1])
                self.startnonce = msg[2]
                self.target = msg[3]
                self.log.debug('Worker %d starts job %r',
                               self.taskid, self.job.jobid)

    def solver(self):

        # TODO : run solver
        time.sleep(1)

        self.itercnt += 1

        # TODO : process solutions
        # TODO : submit solutions within target

        # Send statistics to main process.
        msg = ('stats', self.itercnt, self.solcnt)
        self.conn.send(msg)


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

        self.log.info('Creating worker %d' % taskid)

        # Create worker process and start.
        self.proc = multiprocessing.Process(target=self._run,
                                            args=(taskid, conn2, hugetlb))
        self.proc.start()

        # Listen to messages from worker.
        eventloop.add_reader(self.conn, self._readyRead)

    def close(self):
        """Stop worker and clean up worker process."""

        self.log.info('Stopping worker %d' % self.taskid)

        # Send command to close worker.
        msg = ('close',)
        self.conn.send(msg)
        self.conn.close()
        self.conn = None

        # Clean up worker process.
        self.proc.join()
        self.proc = None

        self.log.info('Worker %d cleaned up' % self.taskid)

    def pause(self):
        """Pause worker."""

        msg = ('pause',)
        self.conn.send(msg)

    def startJob(self, job, startnonce, target):

        msg = ('job', tuple(job), startnonce, target)
        self.conn.send(msg)

    def _readyRead(self):
        """Called when the worker process sends a message."""

        try:
            msg = self.conn.recv()
        except EOFError as e:
            # This happens if the worker fails to initialize or if
            # it crashes. There is no sensible way to continue at this
            # point, so stop the miner.
            self.log.error('Lost connection to worker %d', self.taskid)
            self.manager.terminate()

        if msg[0] == 'submit':
            job      = JobStruct(*msg[1])
            nonce    = msg[2]
            solution = msg[3]
            self.manager.submit(job, nonce, solution)

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
    def _run(taskid, conn, hugetlb):
        """Main function inside worker process."""

        worker = Worker(taskid, conn, hugetlb)
        worker.run()


############################################################
# Stratum client
############################################################

JobStruct = collections.namedtuple('JobStruct', 'jobid header bntime nonce1')


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
        self.sessionid  = None
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

        self.conn.settimeout(self.TIMEOUT)

        self.eventloop.add_reader(self.conn, self._readyRead)

        self.log.info('Subscribing to pool')

        self.sendRequest(method="mining.subscribe",
                         params=[],
                         completion=self._subscribed)

    def close(self):
        """Close connection to pool."""

        self.job    = None
        self.sessionid = None
        self.nonce1 = None
        self.target = None
        self.inbuf  = b''
        self.pendingCompletion = { }

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
                   BytesToHex(job.jobntime),
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
            self.conn.send(reqstr.encode() + b'\n')
        except OSError as e:
            self.log.error(type(e) + ': ' + str(e))
            self.close()
            self.manager.poolConnectionDown()

    def _subscribed(self, result, err):
        """Called when the pool answers our subscribe request."""

        self.log.debug("mining.subscribe result=%r", result)

        try:
            if len(result) < 2:
                raise ValueError('Invalid subscription result (need 2 values)')
            self.nonce1 = HexToBytes(result[0])
            if len(self.nonce1) > 28:
                raise ValueError('Got nonce1 length %d (maximum is 28)' %
                                 len(self.nonce1))
            self.sessionid = result[1]
        except (TypeError, ValueError) as e:
            self.log.error(type(e) + ': ' + str(e))
            self.log.error('mining.subscribe result=%r, error=%r', result, err)
            self.close()
            self.manager.poolConnectionDown()
            return

        self.log.info('Subscribed to pool session=%s', self.sessionid)

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
                s = self.conn.recv(4096, socket.MSG_DONTWAIT)
            except BlockingIOError:
                # No more data available.
                break

            if not s:
                # Socket closed by server.
                self.log.warning('Connection closed by pool')
                self.close()
                break

            self.inbuf += s

            # Decode messages from server.
            while self.conn is not None:

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
                    self.log.error(type(e) + ': ' + str(e))

                if msg is not None:
                    self._handleMessage(msg)

    def _handleMessage(self, msg):
        """Handle a JSON message from the pool."""

        try:
            err    = msg.get('error')
            reqid  = msg.get('id')
            result = msg.get('result')
        except (TypeError, AttributeError) as e:
            self.log.error('Invalid RPC message %r', msg)
            return
            
        if err:
            self.log.error("RPC error %r", err)

        if reqid is not None and result is not None:
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
                    raise ValueError('Got job version len %d (expecting 4)',
                                     len(bversion))
                if len(bprevhash) != 32:
                    raise ValueError('Got job prevhash len %d (expecting 32)',
                                     len(bprevhash))
                if len(bmerkleroot) != 32:
                    raise ValueError('Got job merkleroot len %d (expecting 32)',
                                     len(bmerkleroot))
                if len(breserved) != 32:
                    raise ValueError('Got job reserved len %d (expecting 32)',
                                     len(breserved))
                if len(bntime) != 4:
                    raise ValueError('Got job ntime len %d (expecting 4)',
                                     len(bntime))
                if len(bbits) != 4:
                    raise ValueError('Got job bits len %d (expecting 4)',
                                     len(bbits))
            except (TypeError, ValueError) as e:
                self.log.error(type(e) + ': ' + str(e))
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
                (target,) = params
                targetval = int(target, 16)
                if targetval <= 0 or targetval >= 2**256:
                    raise ValueError('Bad target value')
            except (TypeError, ValueError) as e:
                self.log.error('Bad parameters for mining.set_target %r',
                               params)
                return
            self.log.info('Target changed to %064x', targetval)
            if targetval != self.target:
                self.target = targetval
                self.manager.targetChanged(self.target)

        else:
            self.log.error("Unknown RPC method %r from server", method)


############################################################
# Mining manager
############################################################

class MiningManager:
    """Manages the flow of information between Stratum pool and workers."""

    RECONNECT_INTERVAL  = 10.0
    SHOW_STATS_INTERVAL = 10.0

    StatItem = collections.namedtuple('StatItem',
                                      'time niter nsol nshare score')

    def __init__(self, eventloop):

        self.log = logging.getLogger('manager')
        self.eventloop = eventloop
        self.pool = None
        self.workers = [ ]
        self.firstconnection = True
        self.exitcode = 0
        self.benchmarking = False
        self.stathistory = [ ]

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
            self.stathistory = [ StatItem(time.monotonic(),
                                          0, 0,
                                          self.pool.sharecnt,
                                          self.pool.sharescore) ]
            self.eventloop.call_later(self.SHOW_STATS_INTERVAL, self._showStats)

    def poolConnectionDown(self):
        """Called when the connection to the Stratum pool is lost."""

        if self.firstconnection:
            # First connection failed; just give up now.
            self.terminate()

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

    def submit(self, job, nonce, solution):
        """Called when a worker finds a solution within target."""

        self.pool.submit(job, nonce, solution)

    def terminate(self):
        """Terminate miner after fatal error."""

        self.log.warning('Terminating miner')
        self.exitcode = 1
        self.eventloop.stop()

    def _showStats(self):
        """Show statistics."""

        totaliter = sum([ wh.itercnt for wh in self.workers ])
        totalsol  = sum([ wh.solcnt  for wh in self.workers ])

        h0 = self.stathistory[0]
        h1 = StatItem(time.monotonic(),
                      totaliter, totalsol,
                      self.pool.sharecnt,
                      self.pool.sharescore)
        self.stathistory.append(h1)
        self.stathistory = self.stathistory[-30:]

        dtime  = h1.time  - h0.time
        diter  = h1.niter - h0.niter
        dsol   = h1.nsol  - h0.nsol
        dscore = h1.score - h0.score

        iter_rate  = diter / dtime
        sol_rate   = dsol  / dtime
        share_rate = 3600 * dshare / dtime
        luck = 0 if diter == 0 else dscore / (2.0 * diter)
        self.log.info('%.3f run/s, %.3f Sol/s, %.3f share/hr (%d%% luck)',
                      iter_rate, sol_rate, share_rate, round(100 * luck))

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

            self.log.info('%d runs, %d solutions in %.6f seconds',
                          totaliter, totalsol, duration)
            self.log.info('%.3f run/s, %.3f Sol/s',
                          iter_rate, sol_rate)
            self.eventloop.stop()

        elif self.iterdone % 5 == 0:

            self.log.info('%d runs in %.6f seconds',
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
            print("ERROR: Missing required argument -l", 
                  file=sys.stderr)
            sys.exit(1)

        if args.u is None:
            print("ERROR: Missing required argument -u",
                  file=sys.stderr)
            sys.exit(1)

        w = args.l.split(':')
        if len(w) != 2:
            print("ERROR: Invalid -l argument, expecting 'host:port'",
                  file=sys.stderr)
            sys.exit(1)

        host = w[0]
        try:
            port = int(w[1])
        except ValueError:
            print("ERROR: Invalid -l argument, expecting 'host:port'",
                  file=sys.stderr)
            sys.exit(1)

    if args.t < 1 or args.t > 100:
        print("ERROR: Invalid -t argument, expecting value from 1 to 100",
              file=sys.stderr)
        sys.exit(1)

    if args.b is not None and args.b < 1:
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
    workers = [ ]
    for i in range(args.t):
        wh = WorkerHandle(eventloop=eventloop,
                          manager=manager,
                          taskid=i+1,
                          hugetlb=hugetlb)
        workers.append(wh)
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
        eventloop.call_soon(stratum.connect)

    # Main loop.
    eventloop.run_forever()

    # Stop workers.
    for wh in workers:
        wh.close()

    sys.exit(manager.exitcode)


if __name__ == '__main__':
    main()

