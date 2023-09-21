import unittest
from gradescope_utils.autograder_utils.decorators import weight
from gradescope_utils.autograder_utils.files import check_submitted_files
from gbn_tester import GBNTester
from gbn_host import GBNHost

class TestFastArrival(unittest.TestCase):
    def setUp(self):
        pass
    
    def tearDown(self):
        pass

    @weight(8)
    def test_fast_arrival_no_corruption_no_loss(self):
        tests = [
            "Test9_FastDataRate_0Loss_0Corruption"
        ]

        test_manager = GBNTester(GBNHost)
        score = test_manager.run_tests(tests)

        self.assertTrue(score[0]['passed'], score[0]['errors'])
        print('Passed test successfully')


    @weight(3)
    def test_fast_arrival_no_corruption_10_loss(self):
        tests = [
            "Test10_FastDataRate_10Loss_0Corruption"
        ]

        test_manager = GBNTester(GBNHost)
        score = test_manager.run_tests(tests)

        self.assertTrue(score[0]['passed'], score[0]['errors'])
        print('Passed test successfully')


    @weight(3)
    def test_fast_arrival_10_corruption_no_loss(self):
        tests = [
            "Test11_FastDataRate_0Loss_10Corruption"
        ]

        test_manager = GBNTester(GBNHost)
        score = test_manager.run_tests(tests)

        self.assertTrue(score[0]['passed'], score[0]['errors'])
        print('Passed test successfully')


    @weight(2)
    def test_fast_arrival_10_corruption_10_loss(self):
        tests = [
            "Test12_FastDataRate_10Loss_10Corruption"
        ]

        test_manager = GBNTester(GBNHost)
        score = test_manager.run_tests(tests)

        self.assertTrue(score[0]['passed'], score[0]['errors'])
        print('Passed test successfully')
