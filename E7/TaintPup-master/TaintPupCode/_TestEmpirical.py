import unittest 
import _test_constants
import EmpiricalAnalysis 
import orchestra 

class TestAffectsEmpirically( unittest.TestCase ):

    def setUp(self):   
        self.scriptList  = [ _test_constants._empirical_script_ip,  _test_constants._empirical_script_http, _test_constants._empirical_script_secret, _test_constants._empirical_script_empty, _test_constants._empirical_script_d_adm, _test_constants._empirical_script_md5 ]  
        self.scriptRes   = [ orchestra.doFullTaintForSingleScript( x_  ) for x_ in self.scriptList  ]
        # res_tuple = orchestra.doFullTaintForSingleScript( pp_file  )

    def testInvalidIPEffects(self):     
        affectCount = EmpiricalAnalysis.mineNotUsedSmells( self.scriptRes[0] )[0][0][-1] 
        self.assertEqual(2, affectCount ,  _test_constants.common_error_string + str(2)  )   

    def testHTTPEffects(self):     
        affectCount = EmpiricalAnalysis.mineNotUsedSmells( self.scriptRes[1] )[1][0][-1] 
        self.assertEqual(6, affectCount ,  _test_constants.common_error_string + str(6)  )   

    def testSecretEffects(self):     
        affectCount = EmpiricalAnalysis.mineNotUsedSmells( self.scriptRes[2] )[2][0][-1] 
        self.assertEqual(19, affectCount ,  _test_constants.common_error_string + str(19)  )   

    def testEmptyPassEffects(self):     
        affectCount = EmpiricalAnalysis.mineNotUsedSmells( self.scriptRes[3] )[3][0][-1] 
        self.assertEqual(24, affectCount ,  _test_constants.common_error_string + str(24)  )   

    def testDefaultAdminEffects(self):     
        affectCount = EmpiricalAnalysis.mineNotUsedSmells( self.scriptRes[4] )[4][0][-1] 
        self.assertEqual(1, affectCount ,  _test_constants.common_error_string + str(1)  ) 

    def testWeakCryptoEffects(self):     
        affectCount = EmpiricalAnalysis.mineNotUsedSmells( self.scriptRes[5] )[5][0][-1] 
        self.assertEqual(1, affectCount ,  _test_constants.common_error_string + str(1)  ) 


class TestHopsEmpirically( unittest.TestCase ):

    def setUp(self):   
        self.scriptList  = [ _test_constants._empirical_script_ip,  _test_constants._empirical_hop_http, _test_constants._empirical_script_secret, _test_constants._empirical_script_empty, _test_constants._empirical_script_md5 ]  
        self.scriptRes   = [ orchestra.doFullTaintForSingleScript( x_  ) for x_ in self.scriptList  ]

    def testInvalidIPHops(self):     
        hopListCount = len (EmpiricalAnalysis.mineSmellHops( self.scriptRes[0]  )[0]  )
        self.assertEqual(2, hopListCount ,  _test_constants.common_error_string + str(2)  )   

    def testHTTPHops(self):     
        hopListCount = len (EmpiricalAnalysis.mineSmellHops( self.scriptRes[1]  )[1]  )
        self.assertEqual(5, hopListCount ,  _test_constants.common_error_string + str(5)  )   

    def testSecretHops(self):     
        hopListCount = len (EmpiricalAnalysis.mineSmellHops( self.scriptRes[2]  )[2]  )
        self.assertEqual(19, hopListCount ,  _test_constants.common_error_string + str(19)  )   

    def testEmptyPassHops(self):     
        hopListCount = len (EmpiricalAnalysis.mineSmellHops( self.scriptRes[3]  )[3]  )
        self.assertEqual(0, hopListCount ,  _test_constants.common_error_string + str(0)  )   

    def testWeakCryptHops(self):     
        hopListCount = len (EmpiricalAnalysis.mineSmellHops( self.scriptRes[4] )[4]  )
        self.assertEqual(1, hopListCount ,  _test_constants.common_error_string + str(1)  )   

class TestSmellyResourcesEmpirically( unittest.TestCase ):

    def setUp(self):   
        self.scriptList  = [ _test_constants._empirical_script_ip,  _test_constants._empirical_script_http, _test_constants._empirical_script_secret, _test_constants._empirical_script_empty, _test_constants._empirical_script_d_adm, _test_constants._empirical_script_md5 ]  
        self.scriptRes   = [ orchestra.doFullTaintForSingleScript( x_  ) for x_ in self.scriptList  ]

    def testInvalidIPResources(self):     
        resoListCount = len (EmpiricalAnalysis.mineSmellyResources ( self.scriptRes[0]  )[0]  )
        self.assertEqual(2, resoListCount ,  _test_constants.common_error_string + str(2)  )   

    def testHTTPResources(self):     
        resoListCount = len (EmpiricalAnalysis.mineSmellyResources ( self.scriptRes[1]  )[1]  )
        self.assertEqual(14, resoListCount ,  _test_constants.common_error_string + str(14)  )   

    def testSecretResources(self):     
        resoListCount = len (EmpiricalAnalysis.mineSmellyResources ( self.scriptRes[2]  )[2]  )
        self.assertEqual(74, resoListCount ,  _test_constants.common_error_string + str(74)  )   

    def testEmptyPassResources(self):     
        resoListCount = len (EmpiricalAnalysis.mineSmellyResources ( self.scriptRes[3]  )[3]  )
        self.assertEqual(576, resoListCount ,  _test_constants.common_error_string + str(576)  )   

    def testDefaultAdminResources(self):     
        resoListCount = len (EmpiricalAnalysis.mineSmellyResources ( self.scriptRes[4]  )[4]  )
        self.assertEqual(1, resoListCount ,  _test_constants.common_error_string + str(1)  )   

    def testWeakCryptResources(self):     
        resoListCount = len (EmpiricalAnalysis.mineSmellyResources ( self.scriptRes[5]  )[5]  )
        self.assertEqual(1, resoListCount ,  _test_constants.common_error_string + str(1)  )   


if __name__ == '__main__':
    unittest.main()
