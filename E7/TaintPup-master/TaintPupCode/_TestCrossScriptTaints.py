import graph
import unittest 
import _test_constants
import parser 
import orchestra 

'''
Note to self: 
everytime we use var_tracker_list from `graph` , we need to clear this list as it is global ... code in graph.py does not clear it 
'''

class TestCrossScriptTaint( unittest.TestCase ):
    def testCrossScriptClassCount(self):            
        _, dict_clas, _, _, _, _, _ = parser.executeParser( _test_constants._cross_taint_script_1 ) 
        self.assertEqual(  7 , len(dict_clas)  ,  _test_constants._cross_taint_msg_1 ) 

    def testCrossScriptAttrCountV1(self):            
        _, dict_clas, _, _, _, _, _ = parser.executeParser( _test_constants._cross_taint_script_1 ) 
        self.assertEqual(  5 , len(dict_clas[2][-1])  ,  _test_constants.common_error_string + str(5) ) 

    def testCrossScriptAttrCountV2(self):            
        _, dict_clas, _, _, _, _, _ = parser.executeParser( _test_constants._cross_taint_script_1 ) 
        self.assertEqual(  0 , len(dict_clas[1][-1])  ,  _test_constants.common_error_string + str(0) ) 

    def testCrossScriptAttrCountV3(self):            
        _, dict_clas, _, _, _, _, _ = parser.executeParser( _test_constants._cross_taint_script_1 ) 
        self.assertEqual(  1 , len(dict_clas[7][-1])  ,  _test_constants.common_error_string + str(1) ) 

    def testCrossScriptVarCount(self):            
        _, dict_clas, _, _, _, _, _ = parser.executeParser( _test_constants._cross_taint_script_1 ) 
        self.assertEqual(  0 , len(dict_clas[5][-2])  ,  _test_constants.common_error_string + str(0) ) 

    def testCrossScriptReff(self):            
        _, dict_clas, _, _, _, _, _ = parser.executeParser( _test_constants._cross_taint_script_1 ) 
        scripts2Track = orchestra.getReferredScripts( dict_clas , _test_constants._cross_taint_script_1 )
        self.assertEqual(  6 , len( scripts2Track )  ,  _test_constants.common_error_string + str(6) ) 

    def testCrossScriptSecretV1(self):            
        _, dict_clas, _, _, _, _, _ = parser.executeParser( _test_constants._cross_taint_script_1 ) 
        scripts2Track = orchestra.getReferredScripts( dict_clas , _test_constants._cross_taint_script_1 ) 
        secret_dict  = orchestra.getCrossScriptSecret( scripts2Track, dict_clas ) 
        self.assertEqual(2, len(secret_dict) ,  _test_constants.common_error_string + str(2)  ) 

    def testCrossScriptSecretV2(self):            
        _, dict_clas, _, _, _, _, _ = parser.executeParser( _test_constants._cross_taint_script_2 ) 
        scripts2Track = orchestra.getReferredScripts( dict_clas , _test_constants._cross_taint_script_2 ) 
        secret_dict  = orchestra.getCrossScriptSecret( scripts2Track, dict_clas ) 
        self.assertEqual(4, len(secret_dict) ,  _test_constants.common_error_string + str(4)  ) 

    def testCrossScriptSecretV3(self):            
        _, dict_clas, _, _, _, _, _ = parser.executeParser( _test_constants._cross_taint_script_3 ) 
        scripts2Track = orchestra.getReferredScripts( dict_clas , _test_constants._cross_taint_script_3 ) 
        secret_dict  = orchestra.getCrossScriptSecret( scripts2Track, dict_clas ) 
        self.assertEqual(2, len(secret_dict) ,  _test_constants.common_error_string + str(2)  ) 

    def testCrossScriptSecretV4(self):            
        _, dict_clas, _, _, _, _, _ = parser.executeParser( _test_constants._cross_taint_script_4 ) 
        scripts2Track = orchestra.getReferredScripts( dict_clas , _test_constants._cross_taint_script_4 ) 
        secret_dict  = orchestra.getCrossScriptSecret( scripts2Track, dict_clas ) 
        self.assertEqual(0, len(secret_dict) ,  _test_constants.common_error_string + str(0)  ) 


    def testCrossScriptSecretV5(self):            
        _, dict_clas, _, _, _, _, _ = parser.executeParser( _test_constants._cross_taint_script_5 ) 
        scripts2Track = orchestra.getReferredScripts( dict_clas , _test_constants._cross_taint_script_5 ) 
        secret_dict  = orchestra.getCrossScriptSecret( scripts2Track, dict_clas ) 
        self.assertEqual(4, len(secret_dict) ,  _test_constants.common_error_string + str(4)  ) 

    def testCrossScriptSecretV6(self):            
        _, dict_clas, _, _, _, _, _ = parser.executeParser( _test_constants._cross_taint_script_6 ) 
        scripts2Track = orchestra.getReferredScripts( dict_clas , _test_constants._cross_taint_script_6 ) 
        secret_dict  = orchestra.getCrossScriptSecret( scripts2Track, dict_clas ) 
        self.assertEqual(1, len(secret_dict) ,  _test_constants.common_error_string + str(1)  )   

    def testCrossScriptSecretV7(self):            
        _, dict_clas, _, _, _, _, _ = parser.executeParser( _test_constants._cross_taint_script_7 ) 
        scripts2Track = orchestra.getReferredScripts( dict_clas , _test_constants._cross_taint_script_7 ) 
        secret_dict  = orchestra.getCrossScriptSecret( scripts2Track, dict_clas ) 
        self.assertEqual(2, len(secret_dict) ,  _test_constants.common_error_string + str(2)  )

    def testCrossScriptSecretV8(self):            
        _, dict_clas, _, _, _, _, _ = parser.executeParser( _test_constants._cross_taint_script_8 ) 
        scripts2Track = orchestra.getReferredScripts( dict_clas , _test_constants._cross_taint_script_8 ) 
        secret_dict  = orchestra.getCrossScriptSecret( scripts2Track, dict_clas ) 
        self.assertEqual(1, len(secret_dict) ,  _test_constants.common_error_string + str(1)  )        

    def testCrossScriptInavlidIP(self):            
        _, dict_clas, _, _, _, _, _ = parser.executeParser( _test_constants._cross_taint_script_ip ) 
        scripts2Track = orchestra.getReferredScripts( dict_clas , _test_constants._cross_taint_script_ip ) 
        ip_dict  = orchestra.getCrossScriptInvalidIP( scripts2Track, dict_clas ) 
        self.assertEqual(1, len(ip_dict) ,  _test_constants.common_error_string + str(1)  )        

    def testCrossScriptInsecureHTTPV1(self):            
        _, dict_clas, _, _, _, _, _ = parser.executeParser( _test_constants._cross_taint_script_http ) 
        scripts2Track = orchestra.getReferredScripts( dict_clas , _test_constants._cross_taint_script_http ) 
        http_dict  = orchestra.getCrossScriptHTTP ( scripts2Track, dict_clas ) 
        self.assertEqual(1, len(http_dict) ,  _test_constants.common_error_string + str(1)  )        

    def testCrossScriptInsecureHTTPV2(self):            
        _, dict_clas, _, _, _, _, _ = parser.executeParser( _test_constants._cross_taint_script_7 ) 
        scripts2Track = orchestra.getReferredScripts( dict_clas , _test_constants._cross_taint_script_7 ) 
        http_dict  = orchestra.getCrossScriptHTTP ( scripts2Track, dict_clas ) 
        self.assertEqual(3, len(http_dict) ,  _test_constants.common_error_string + str(3)  )

    def testCrossScriptInsecureHTTPV3(self):            
        _, dict_clas, _, _, _, _, _ = parser.executeParser( _test_constants._cross_taint_script_3 ) 
        scripts2Track = orchestra.getReferredScripts( dict_clas , _test_constants._cross_taint_script_3 ) 
        http_dict  = orchestra.getCrossScriptHTTP ( scripts2Track, dict_clas ) 
        self.assertEqual(2, len(http_dict) ,  _test_constants.common_error_string + str(2)  )    

    def testCrossScriptEmptyPass(self):            
        _, dict_clas, _, _, _, _, _ = parser.executeParser( _test_constants._cross_taint_script_3 ) 
        scripts2Track = orchestra.getReferredScripts( dict_clas , _test_constants._cross_taint_script_3 ) 
        _dict  = orchestra.getCrossScriptEmptyPass ( scripts2Track, dict_clas ) 
        self.assertEqual(1, len(_dict) ,  _test_constants.common_error_string + str(1)  )                       

if __name__ == '__main__':
    unittest.main()
