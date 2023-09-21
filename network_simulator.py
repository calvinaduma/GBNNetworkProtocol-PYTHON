import sys, copy, random, logging, struct
from enum import Enum, IntEnum

class NetworkSimulator():

    # *********************** Simulator routines ***********************
    # ************ DO NOT CALL ANY ROUTINES IN THIS SECTION ************
    # *********** ROUTINES FOR STUDENT USE CAN BE FOUND BELOW **********
    def __init__(self, options, RDTHost):
        self.continue_simulation = True
        self.event_list = []

        # Configuration for the packet simulation
        self.max_events = options.num_pkts              # number of msgs to generate, then stop
        self.timer_interval = options.timer_interval     
        self.lossprob = options.loss_prob               # probability that a packet is dropped
        self.corruptprob = options.corrupt_prob         # probability that one bit is packet is flipped
        self.arrival_rate = options.arrival_rate        # arrival rate of messages from layer 5

        # Record statistics of what has happened to packets in our simulated network
        self.num_events = 0
        self.time = 0.000       #
        self.nsim = 0           # number of messages from 5 to 4 so far
        self.ntolayer3 = 0      # number sent into layer 3
        self.nlost = 0          # number lost in media
        self.ncorrupt = 0       # number corrupted by media
        
        # If we specify a seed, initialize random with it
        if options.seed:
            random.seed(options.seed)

        # Create the two hosts we will be simulating
        self.A = RDTHost(self, EventEntity.A, self.timer_interval, 5)
        # These variables will be used by the testing suite
        self.A.num_data_sent = 0
        self.A.num_ack_sent = 0
        self.A.num_data_received = 0
        self.A.num_ack_received = 0
        self.A.data_sent = []
        self.A.data_received = []
               
        self.B = RDTHost(self, EventEntity.B, self.timer_interval, 5)
        self.B.num_data_sent = 0
        self.B.num_ack_sent = 0
        self.B.num_data_received = 0
        self.B.num_ack_received = 0
        self.B.data_sent = []
        self.B.data_received = []
        
        self.Host = {
            EventEntity.A: self.A,
            EventEntity.B: self.B,
        }

        # Generate the first event
        self.generate_next_arrival()


    def Simulate(self):
        print("-----  Sliding Window Network Simulator Version -------- \n")

        events = []

        while self.continue_simulation:
            # Check to see if we have any more events to simulate
            if len(self.event_list) == 0:
                self.continue_simulation = False
                #self.trace("Simulator terminated at time {} after sending {} msgs from layer5\n".format(self.time, self.nsim), 0)
                print("Simulator terminated at time {} after sending {} msgs from layer5\n".format(self.time, self.nsim))
            else:
                # Get the next event to simulate
                cur_event = self.event_list.pop(0)
                events.append(cur_event)

                # update our time value to the time of the next event
                self.time = cur_event.evtime 

                # This is an event containing new data from the application layer
                if cur_event.evtype == EventType.FROM_LAYER5:
                    # Set up the next packet to arrive after this one
                    self.generate_next_arrival()

                    payload = self.generate_payload()

                    # Incrememnt the number of packets that have been simulated
                    self.nsim += 1

                    # Log this event
                    self.Host[cur_event.eventity].data_sent.append(payload)
                    self.print_entity_message(cur_event.eventity, "Rcvd from Application Layer: %s" % payload, None)

                    # Send this message to the assigned host
                    self.Host[cur_event.eventity].receive_from_application_layer(payload)

                # This is an event being passed up from the network layer
                elif cur_event.evtype == EventType.FROM_LAYER3:
                    # Log this event
                    self.print_entity_message(cur_event.eventity, "Rcvd from Network Layer", cur_event.pkt)

                    # Send this message to the assigned host
                    self.Host[cur_event.eventity].receive_from_network_layer(cur_event.pkt)

                # This is a timer interrupt event
                elif cur_event.evtype == EventType.TIMER_INTERRUPT:
                    self.print_entity_message(cur_event.eventity, "Timer Interrupt", None)
                    self.Host[cur_event.eventity].timer_interrupt()
            
        return events


    def opposite_entity(self, entity):
        if entity == EventEntity.A:
            return EventEntity.B
        else: 
            return EventEntity.A

    def unpack_pkt(self, byte_data):
        try:
            # First, unpack the fixed length header
            header = struct.unpack("!HiHI", byte_data[:12])
            
            # Check to see if the length of the packet is greater
            # than zero. If so, unpack the payload
            if header[3] > 0:
                payload = struct.unpack("!%is"%header[3], byte_data[12:])[0].decode()
            else:
                payload = None

            pkt = Packet(header, payload, byte_data)
            return pkt
        except Exception as e:
            return None

    
    def print_entity_message(self, entity, message, bytes):
        msg = "{} @ {:.4f}: {}".format(entity.name, self.time, message)

        if bytes:
            pkt = self.unpack_pkt(bytes)
            if pkt:
                type = "Data"
                if pkt.pkt_type == 0:
                    type = "ACK"
                msg += ": [TYPE: %s, NUM: %i, CKSUM: %i, LEN: %i" % (type, pkt.pkt_number, pkt.checksum, pkt.length)
                #msg += ": [SEQ: %i, ACK: %i, ACK_FLAG: %s, CKSUM: %i, LEN: %i" % (pkt.seqnum, pkt.acknum, str(pkt.ackflag), pkt.checksum, pkt.length)
                if pkt.length > 0:
                    msg += ", PAYLOAD: %s]" % pkt.payload
                else:
                    msg += "]"

        print(msg)


    def generate_payload(self):
        # Create a simulated message for this packet
        j = self.nsim % 26
        msg2give = ""
        length = random.randint(2, 5)
        for i in range(0,length):
            msg2give += chr(97 + j)
        return msg2give


    def generate_next_arrival(self):
        if self.num_events < self.max_events:
            self.num_events += 1

            # Create a new simulated event
            new_event = SimulatedEvent()

            # Determine when this simulated event will occur
            x = self.arrival_rate*random.uniform(0.0, 1.0)*2  # x is uniform on [0,2*lambda], having mean of lambda
            new_event.evtime = self.time + x

            # Specify that this event is coming from the application layer
            new_event.evtype = EventType.FROM_LAYER5

            # Determine which host is receiving this event, A or B
            if random.uniform(0.0, 1.0) > 0.5:
                new_event.eventity = EventEntity.A
            else:
                new_event.eventity = EventEntity.B

            # Insert the new event into our event list
            self.insert_event(new_event)


    def insert_event(self, new_event):
        # If queue is empty, add as head and don't connect any adjacent events
        if len(self.event_list) == 0:
            self.event_list.append(new_event)
        else:
            # check to see if this event occurs before the first element
            if new_event.evtime < self.event_list[0].evtime:
                self.event_list.insert(0, new_event)
            # check to see if this event occurs after the last element\
            elif new_event.evtime > self.event_list[-1].evtime:
                self.event_list.append(new_event)
            else:
                for idx, e in enumerate(self.event_list):
                    if new_event.evtime < e.evtime:
                        self.event_list.insert(idx, new_event)
                        break


    def print_event_list(self, trace_level):
        for e in self.event_list:
            #self.trace("Event time: {}, type: {} entity: {}".format(e.evtime, e.evtype, e.eventity),trace_level)
            pass



    # ******** DO NOT CALL ANY ROUTINES IN Simulator ABOVE THESE LINES ********
    # *********************** Student callable routines ***********************
    # ********* You will need to call the routines below these lines **********
    

    def stop_timer(self, entity):
        for idx, e in enumerate(self.event_list):
            if e.eventity == entity:
                if e.evtype == EventType.TIMER_INTERRUPT:
                    self.event_list.pop(idx)    # Remove the first timer event associated with this entity
                    self.print_entity_message(entity, "Stopping Timer", None)
                    return
                else:
                    # No timer event to stop
                    pass
        self.print_entity_message(entity, "ERROR: ATTEMPTED TO STOP A TIMER BUT NONE WERE RUNNING", None)
        


    def start_timer(self, entity, increment):
        # Check to see if a timer has already been started
        for e in self.event_list:
            if e.evtype == EventType.TIMER_INTERRUPT and e.eventity == entity:
                self.print_entity_message(entity, "ERROR: ATTEMPTED TO START TIMER WHILE ONE IS ALREADY RUNNING", None)
                return

        self.print_entity_message(entity, "Starting Timer", None)

        new_event = SimulatedEvent()
        new_event.evtime = self.time + increment
        new_event.evtype = EventType.TIMER_INTERRUPT
        new_event.eventity = entity
        self.insert_event(new_event)



    def pass_to_network_layer(self, entity, packet, is_ACK = False):
        self.ntolayer3 += 1

        if is_ACK:
            self.Host[entity].num_ack_sent += 1
        else:
            self.Host[entity].num_data_sent += 1

        self.print_entity_message(entity, "Passing to Network Layer", packet)

        # Simulate losses
        if random.uniform(0.0, 1.0) < self.lossprob:
            self.nlost += 1
            self.print_entity_message(entity, "LOSING PACKET!", None)
            #self.trace("TOLAYER3: PACKET BEING LOST", 0)
            return

        if is_ACK:
            self.Host[self.opposite_entity(entity)].num_ack_received += 1
        else:
            self.Host[self.opposite_entity(entity)].num_data_received += 1

        # make a copy of the packet student just gave me since he/she may decide
        # to do something with the packet after we return back to him/her
        pkt = copy.deepcopy(packet)
        try:
            #self.trace("TOLAYER3: seq: {}, ack {}, check: {}, {}".format(pkt.seqnum, pkt.acknum, pkt.checksum, pkt.payload), 2)
            pass
        except Exception as e:
            pass

        new_event = SimulatedEvent()
        new_event.evtype = EventType.FROM_LAYER3
        new_event.eventity = EventEntity((int(entity)+1) % 2)     # event occurs at the other entity
        new_event.pkt = pkt

        # finally, compute the arrival time of packet at the other end.
        # medium can not reorder, so make sure packet arrives between 1 and 10
        # time units after the latest arrival time of packets
        # currently in the medium on their way to the destination
        last_time = self.time
        for e in self.event_list:
            if e.evtype == EventType.FROM_LAYER3 and e.eventity == entity:
                last_time = e.evtime
        new_event.evtime = last_time + 0.1 + 0.9*random.uniform(0.0, 1.0)

        # simulate corruption
        if random.uniform(0.0, 1.0) < self.corruptprob:
            self.ncorrupt += 1
            self.print_entity_message(entity, "CORRUPTING PACKET!", None)

            # Flip a random bit
            bytenum = random.randint(0, len(pkt)-1)
            bitnum = random.randint(0, 7)
            values = bytearray(pkt)
            altered_value = values[bytenum]
            bit_mask = 1 << bitnum
            values[bytenum] = altered_value ^ bit_mask
            new_event.pkt = bytes(values)

        #self.trace("TOLAYER3: scheduling arrival on other side", 2)
        self.insert_event(new_event)


    def pass_to_application_layer(self, entity, data):
        # Log this event
        self.Host[entity].data_received.append(data)
        self.print_entity_message(entity, "Passing to Application Layer: %s" % data, None)
    

class SimulatedEvent():
    def __init__(self):
        self.evtime = 0
        self.evtype = None
        self.eventity = None
        self.pkt = None
        self.previous_event = None
        self.next_event = None



class Packet():
    def __init__(self, header, payload, bytes):
        self.pkt_type = header[0]
        self.pkt_number = header[1]
        self.checksum = header[2]
        self.length = header[3]
        self.payload = payload
        self.bytes = bytes
        

class EventType(Enum):
    FROM_LAYER5 = 1
    FROM_LAYER3 = 2
    TIMER_INTERRUPT = 3


class EventEntity(IntEnum):
    A = 0
    B = 1