from network_simulator import NetworkSimulator, Packet, EventEntity
from enum import Enum
from struct import pack, unpack

class GBNHost():

    # The __init__ method accepts:
    # - a reference to the simulator object
    # - the value for this entity (EntityType.A or EntityType.B)
    # - the interval for this entity's timer
    # - the size of the window used for the Go-Back-N algorithm
    def __init__(self, simulator, entity, timer_interval, window_size):
        
        # These are important state values that you will need to use in your code
        self.simulator = simulator
        self.entity = entity
        
        # Sender properties
        self.timer_interval = timer_interval        # The duration the timer lasts before triggering
        self.window_size = window_size              # The size of the seq/ack window
        self.window_base = 0                        # The last ACKed packet. This starts at 0 because no packets 
                                                    # have been ACKed
        self.next_seq_num = 0                       # The SEQ number that will be used next
        self.unACKed_buffer = []                    # buffer of unACKed packets [bytes]
        self.appLayer_buffer = []                   # buffer for application layer [strings]
        self.isACK = False
        self.expected_seq_num = 0
        self.ack_pkt = pack("HiHI",0,-1,0,0)

    ###########################################################################################################
    ## Core Interface functions that are called by Simulator

    # This function implements the SENDING functionality. It should implement retransmit-on-timeout. 
    # Refer to the GBN sender flowchart for details about how this function should be implemented

    def receive_from_application_layer(self, payload):
        #GBN Sender
        if self.next_seq_num < self.window_base + self.window_size:
            # [0]pktType [1]pktNum [2]checksum  [3]payloadLength [4]payload
            payloadLength = len(payload)
            payload = payload.encode()
            formatString = "!HiHI" + str(payloadLength) + "s" 
            pkt = pack(formatString,128,self.next_seq_num,0,len(payload),payload)
            pkt = self.compute_checksum(pkt,False)
            self.unACKed_buffer[self.next_seq_num] = pkt
            self.isACK = False
            self.simulator.pass_to_network_layer(self.entity,self.unACKed_buffer[self.next_seq_num],self.isACK)
            if self.window_base == self.next_seq_num:
                self.simulator.start_timer(self.entity,self.timer_interval)
            self.next_seq_num += 1
        
        else:
            self.appLayer_buffer[payload]
            


    # This function implements the RECEIVING functionality. This function will be more complex that
    # receive_from_application_layer(), it includes functionality from both the GBN Sender and GBN receiver
    # FSM's (both of these have events that trigger on receive_from_network_layer). You will need to handle 
    # data differently depending on if it is a packet containing data, or if it is an ACK.
    # Refer to the GBN receiver flowchart for details about how to implement responding to data pkts, and
    # refer to the GBN sender flowchart for details about how to implement responidng to ACKs
    def receive_from_network_layer(self, byte_data):
        # GBN Receiver
        if self.isACK == False: # data pkt
            formatString = "!HiHI" + str(len(byte_data)-2) + "s"
            try:
                pktLength = unpack(formatString,byte_data)[3]
                get_seq_num = unpack(formatString,byte_data)[1]
                # [0]pktType [1]pktNum [2]checksum  [3]payloadLength [4]payload
                if self.is_corrupt(byte_data) == False and get_seq_num == self.expected_seq_num:
                        data = unpack(formatString,byte_data)[4]
                        data.decode()
                        self.simulator.pass_to_application_layer(self.entity,data)
                        self.isACK = True
                        self.ack_pkt = pack("HiHI",0,self.expected_seq_num,0,0)
                        self.ack_pkt = self.compute_checksum(ack_pkt,True)
                        self.simulator.pass_to_network_layer(self.entity,self.ack_pkt,self.isACK)
                        expected_seq_num += 1
                else:
                    self.isACK = True
                    self.simulator.pass_to_network_layer(self.entity,self.ack_pkt,self.isACK)
            except:
                self.isACK = True
                self.simulator.pass_to_network_layer(self.entity,self.ack_pkt,self.isACK)

        # GBN Sender
        else: # ack pkt
            formatString = "!HiHI"
            try:
                pktLength = unpack(formatString,byte_data)[3]
                ack_num = unpack(formatString,byte_data)[1]
                if ack_num >= self.window_base:
                    self.window_base = ack_num + 1
                    self.simulator.stop_timer(self.entity)
                    if self.window_base != self.next_seq_num:
                        self.simulator.start_timer(self.entity,self.timer_interval)
                    while len(appLayer_buffer) > 0 and self.next_seq_num < (self.window_base + self.window_size):
                        payload = appLayer_buffer.pop()
                        formatString = "!HiHI" + str(len(payload)) + "s" 
                        pkt = pack(formatString,128,self.next_seq_num,0,len(payload),payload)
                        pkt = self.compute_checksum(pkt,False)
                        unACKed_buffer[self.next_seq_num] = pkt
                        self.isACK = False
                        self.simulator.pass_to_network_layer(self.entity,self.unACKed_buffer[self.next_seq_num],self.isACK)
                        if self.window_base == self.next_seq_num:
                            self.simulator.start_timer(self.entity,self.timer_interval)
                        self.next_seq_num += 1
            except:
                pass

    # This function is called by the simulator when a timer interrupt is triggered due to an ACK not being 
    # received in the expected time frame. All unACKed data should be resent, and the timer restarted
    def timer_interrupt(self):
        self.simulator.start_timer(self.entity,self.timer_interval)
        for x in self.unACKed_buffer:
            self.simulator.pass_to_network_layer(self.entity,x,False)

        self.isACK = False
        self.simulator.pass_to_network_layer(self.entity,self.next_seq_num,self.isACK)

    # This function should check to determine if a given packet is corrupt. The packet parameter accepted
    # by this function should contain a byte array
    def is_corrupt(self, packet):
        # [0]pktType [1]pktNum [2]checksum  [3]payloadLength [4]payload
        # ACK
        word = []
        summedWords = 0
        if len(packet % 2) == 1:
            packet += bytes(1)
        for i in range(0,len(packet),2):
            word.append(packet[i] << 8 | packet[i+1])
        for x in word:
            sumedWords += x
        result = (summedWords & 0xffff) + (summedWords >> 16)
        final_result = ~result & 0xffff
        final_result << 8
        if final_checksum == 0xff00:
            return True
        else:
            return False


    # This function calculates the checksum
    # packet is a byte array
    # returns a byte array packet containing new checksum
    def compute_checksum(self,packet,ack):
        # [0]pktType [1]pktNum [2]checksum  [3]payloadLength [4]payload
        word = []
        summedWords = 0
        if len(packet % 2) == 1:
            packet += bytes(1)
        for i in range(0,len(packet),2):
            word.append(packet[i] << 8 | packet[i+1])
        for x in word:
            sumedWords += x
        result = (summedWords & 0xffff) + (summedWords >> 16)
        final_result = ~result & 0xffff

        if ack == True:
            formatString = "!HiHI"
            pktNum = unpack(formatString,packet)[1]
            checksum = final_result
            payloadLength = unpack(formatString,packet)[3]
            packet = pack(formatString,0,pktNum,checksum,payloadLength)
            return packet
        else:
            formatString = "!HiHI" + str(len(packet)) + "s"
            pktNum = unpack(formatString,packet)[1]
            checksum = final_result
            payloadLength = unpack(formatString,packet)[3]
            payload = unpack(formatString,packet)[4]
            packet = pack(formatString,128,pktNum,checksum,payloadLength,payload)
            return packet