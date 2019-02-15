#!/usr/bin/python

import asyncio, logging, traceback, subprocess, re, os
from pyrad.dictionary import Dictionary
from pyrad.server_async import ServerAsync
from pyrad.packet import AccessAccept
from pyrad.server import RemoteHost

try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except:
    pass

logging.basicConfig(level="INFO",
                    format="%(asctime)s [%(levelname)-8s] %(message)s")

class DAEServer(ServerAsync):

    def __init__(self, loop, dictionary):

        ServerAsync.__init__(self, loop=loop, dictionary=dictionary,
                             enable_pkt_verify=True, debug=True)

    def handle_auth_packet(self, protocol, pkt, addr):

        print("Received an authentication request with id ", pkt.id)
        print('Authenticator ', pkt.authenticator.hex())
        print('Secret ', pkt.secret)
        print("Attributes: ")
        for attr in pkt.keys():
            print("%s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt, **{
            "Service-Type": "Framed-User",
            "Framed-IP-Address": '192.168.0.1',
            "Framed-IPv6-Prefix": "fc66::1/64"
        })

        reply.code = AccessAccept
        protocol.send_response(reply, addr)

    def handle_acct_packet(self, protocol, pkt, addr):

        print("Received an accounting request")
        print("Attributes: ")
        for attr in pkt.keys():
            print("%s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt)
        protocol.send_response(reply, addr)

    def handle_coa_packet(self, protocol, pkt, addr):

        print("Received an coa request")
        print("Attributes: ")
        for attr in pkt.keys():
            print("%s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt)
        protocol.send_response(reply, addr)

    def handle_disconnect_packet(self, protocol, pkt, addr):

        #print("Received an disconnect request")
        #print("Attributes: ")
        #for attr in pkt.keys():
        #    print("%s: %s" % (attr, pkt[attr]))
        reply = self.CreateReplyPacket(pkt)
        # Disconnect NAK
        reply.code = 42

        if "User-Name" in pkt and "NAS-Port" in pkt:
            acct_session_id = pkt["Acct-Session-Id"][0]

            user_name = pkt["User-Name"][0]
            nas_port = pkt["NAS-Port"][0]
            #self.logger.info("GOT NAS-PORT %s"%nas_port)

            proc1 = subprocess.Popen("strongswan statusall".split(" "), stdout=subprocess.PIPE)
            proc2 = subprocess.Popen(['grep', "%s"%user_name], stdin=proc1.stdout,
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc3 = subprocess.Popen(['grep', "\[%s\]"%nas_port], stdin=proc2.stdout,
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc1.stdout.close()
            proc2.stdout.close()
            out, err = proc3.communicate()
            connection_exists = re.search("Remote EAP identity|ESTABLISHED",out.decode("UTF-8"))
            if connection_exists:
                cmd = "strongswan down [%s]"%nas_port
                proc4 = subprocess.Popen(cmd.split(" "), stdout=subprocess.PIPE)
                outdown, err = proc4.communicate()
                success = re.search("closed successfully", outdown.decode("UTF-8"))
                if success:
                    self.logger.info("Connection %s %s closed correctly!"%(user_name,nas_port))
                    reply.code = 41
                else:
                    self.logger.info("Connection %s %s Failed to close!"%(user_name,nas_port))
            else:
               self.logger.info("Connection %s %s doesn't exist"%(user_name,nas_port))
            #Disconnect ACK
        else:
            self.logger.info("Incorrect DAE Request")

        protocol.send_response(reply, addr)


if __name__ == '__main__':

    cd = os.path.dirname(os.path.realpath(__file__))
    

    # create server and read dictionary
    loop = asyncio.get_event_loop()
    server = DAEServer(loop=loop, dictionary=Dictionary('%s/dictionary'%cd))

    f = open("%s/secret.txt"%cd)
    secret = f.readline().strip().encode("UTF-8")
    f.close()

    server.hosts["0.0.0.0"] = RemoteHost("127.0.0.1",
                                       secret,
                                       "localhost")

    try:
        # Initialize transports
        loop.run_until_complete(
            asyncio.ensure_future(
                server.initialize_transports(enable_auth=False,
                                             enable_acct=False,
                                             enable_coa=True,
                                             addresses=["0.0.0.0"])))
        try:
            # start server
            loop.run_forever()
        except KeyboardInterrupt as k:
            pass

        # Close transports
        loop.run_until_complete(asyncio.ensure_future(
            server.deinitialize_transports()))

    except Exception as exc:
        print('Error: ', exc)
        print('\n'.join(traceback.format_exc().splitlines()))
        # Close transports
        loop.run_until_complete(asyncio.ensure_future(
            server.deinitialize_transports()))

    loop.close()
