import os, json, sys, re
from optparse import OptionParser
from gbn_host import GBNHost
from network_simulator import NetworkSimulator


class GBNTester():
    def __init__(self, RDTImpl):
        self.RDTImpl = RDTImpl

        self.op = OptionParser(
            version="0.1a",
            description="CPSC 3600 IRC Server application")
        self.op.add_option(
            "--num_pkts",
            metavar="X", type="int",
            help="The number of packets to simulate sending")
        self.op.add_option(
            "--timer_interval",
            metavar="X", type="float",
            help="The timer interval")
        self.op.add_option(
            "--loss_prob",
            metavar="X", type="float",
            help="The probability of losing a packet")
        self.op.add_option(
            "--corrupt_prob",
            metavar="X", type="float",
            help="The probability of losing a packet")
        self.op.add_option(
            "--arrival_rate",
            metavar="X", type="float",
            help="The average time between packets arriving from the application layer")
        self.op.add_option(
            "--capture_log",
            action="store_true",
            help="Captures all print output and stores it in a log file")
        self.op.add_option(
            "--seed",
            metavar="X", type="int",
            help="The seed to use for random generation")


    def run_tests(self, tests):
        __location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
        if not os.path.exists(os.path.join(__location__, 'Logs')):
            os.makedirs(os.path.join(__location__, 'Logs'))   

        results = []
        for test in tests:
            # Open the test file
            with open(os.path.join(__location__, 'tests', 'test_cases', '%s.cfg' % test), 'r') as fp:
                test_config = json.load(fp)
                # Redirect all output to a log file for this test
                #with open(os.path.join(__location__, 'Logs', '%s.log' % test), 'w') as log:
                passed, errors = self.run_test(None, test_config)
                results.append({
                    'test':test, 
                    'passed':passed, 
                    'errors':errors
                })
                #sys.stdout = sys.__stdout__
                print("%s passed: %r" % (test, passed))
                if errors:
                    print("%s\n" % errors)
        return results

    def run_test(self, log, test):
        try:
            # https://stackoverflow.com/questions/16710076/python-split-a-string-respect-and-preserve-quotes
            args = re.findall(r'(?:[^\s,"]|"(?:\\.|[^"])*")+', test["options"])

            options, args = self.op.parse_args(args)
            simulator = NetworkSimulator(options, self.RDTImpl)
            
            #if options.capture_log:
            #    sys.stdout = log

            result = simulator.Simulate()

            return self.check_test_results(test, simulator, result)
            
        except Exception as e:
            return False, e


    def check_test_results(self, test, simulator, result):
        problems = ""
        problems += self.check_host(test['final_state']['A'], simulator.A)        
        problems += self.check_host(test['final_state']['B'], simulator.B)
        problems += self.check_simulator(test['final_state']['Simulator'], simulator)
        
        if not problems:
            return True, None
        else:
            return False, problems


    def check_host(self, test, host):
        problems = ""
        
        problems += self.find_problems_with_list(host.entity, "data sent (data_sent)", test['data_sent'], host.data_sent)
        problems += self.find_problems_with_list(host.entity, "data received (data_received)", test['data_received'], host.data_received)
        problems += self.find_problems_with_value(host.entity, "last ACKed value (window_base)", test['window_base'], host.window_base)
        problems += self.find_problems_with_value(host.entity, "data pkts sent (num_data_sent)", test['num_data_sent'], host.num_data_sent)
        problems += self.find_problems_with_value(host.entity, "ACK pkts sent (num_ack_sent)", test['num_ack_sent'], host.num_ack_sent)
        problems += self.find_problems_with_value(host.entity, "data pkts received (num_data_received)", test['num_data_received'], host.num_data_received)
        problems += self.find_problems_with_value(host.entity, "ACK pkts received (num_ack_received)", test['num_ack_received'], host.num_ack_received)
        
        return problems


    def check_simulator(self, test, simulator):
        problems = ""
        
        problems += self.find_problems_with_value("Simulator", "total events", test['num_events'], simulator.num_events)
        problems += self.find_problems_with_value("Simulator", "packets received from layer 5", test['nsim'], simulator.nsim)
        problems += self.find_problems_with_value("Simulator", "pkts sent to layer 3", test['ntolayer3'], simulator.ntolayer3)
        problems += self.find_problems_with_value("Simulator", "lost packets", test['nlost'], simulator.nlost)
        problems += self.find_problems_with_value("Simulator", "corrupt packets", test['ncorrupt'], simulator.ncorrupt)
        
        return problems


    def find_problems_with_list(self, entity, propertyname, desired_list, actual_list):
        problems = ""
        if len(desired_list) != len(actual_list):
            problems += "%s: Wrong number of %s (found %i, expected %i)\n" % (entity, propertyname, len(actual_list), len(desired_list))
        
        missing_from_actual = self.diff(actual_list, desired_list)
        if missing_from_actual:
            problems += "%s: Missing from %s: %s\n" % (entity, propertyname, ", ".join(missing_from_actual))

        extra_in_actual = self.diff(desired_list, actual_list)
        if extra_in_actual:
            problems += "%s: Extra in %s: %s\n" % (entity, propertyname, ", ".join(extra_in_actual))

        return problems


    def find_problems_with_value(self, entity, propertyname, desired_value, actual_value):
        if desired_value != actual_value:
            return "%s: Wrong value for %s (found %s, expected %s)\n" % (entity, propertyname, actual_value, desired_value)
        return ""


    # Helper function to find what differences exist in two lists
    def diff(self, list1, list2):
        return (list(set(list1) - set(list2)))

    def union(self, lst1, lst2): 
        final_list = list(set(lst1) | set(lst2)) 
        return final_list

    def intersect(self, lst1, lst2): 
        final_list = list(set(lst1) & set(lst2)) 
        return final_list


if __name__ == "__main__":
    
    # These public test cases are worth 50 points. When grading your project, we will also run 
    # hidden test cases that are worth 25 points. These test cases cover the same functionality, so 
    # if your code is correct and passes the public test cases, it SHOULD also pass the 
    # hidden test cases. Your grade on the project will be equal to your score on the 
    # public test cases + your score on the hidden test cases. The highest possible score is 75 points
    tests = [
        "Test1_SlowDataRate_0Loss_0Corruption",
        #"Test2_SlowDataRate_25Loss_0Corruption",
        #"Test3_SlowDataRate_0Loss_25Corruption",
        #"Test4_SlowDataRate_25Loss_25Corruption",
        #"Test5_MediumDataRate_0Loss_0Corruption",
        #"Test6_MediumDataRate_10Loss_0Corruption",
        #"Test7_MediumDataRate_0Loss_10Corruption",
        #"Test8_MediumDataRate_10Loss_10Corruption",
        #"Test9_FastDataRate_0Loss_0Corruption",
        #"Test10_FastDataRate_10Loss_0Corruption",
        #"Test11_FastDataRate_0Loss_10Corruption",
        #"Test12_FastDataRate_10Loss_10Corruption",
    ]

    test_manager = GBNTester(GBNHost)
    score = test_manager.run_tests(tests)