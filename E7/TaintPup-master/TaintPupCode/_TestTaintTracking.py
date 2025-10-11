import graph
import unittest 
import _test_constants
import parser 
import orchestra 
import constants 

'''
Note to self: 
everytime we use var_tracker_list from `graph` , we need to clear this list as it is global ... code in graph.py does not clear it 
'''

class TestTaintGraph( unittest.TestCase ):


    def testMultiLevelTaint( self ): 
        _, _, _, dict_of_all_variables, _, _ , _ = parser.executeParser( _test_constants._multi_taint_script_name )
        sink_var =  graph.doMultipleTaint( _test_constants._multi_taint_var_input ,  dict_of_all_variables ) 
        self.assertEqual(  sink_var , _test_constants._multi_taint_var_output, _test_constants._multi_taint_var_error_msg) 
        graph.var_tracker_list.clear() 

    def testLiveness(self):
        _, _, _, dict_of_all_variables, _, _ , _ = parser.executeParser( _test_constants._liveness_script_name )
        for var2test in _test_constants._liveness_var_input_list:
            self.assertTrue( graph.checkLiveness( var2test, dict_of_all_variables ) ,_test_constants._liveness_error_msg  )
            graph.var_tracker_list.clear() 

    def testUnameVarInTaintDict(self):            
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._single_taint_script_name ) 
        _, secret_dict_vars =  orchestra.finalizeHardCodedSecrets( dict_all_attr, dict_all_vari )  
        self.assertTrue( checkVarInSmellDict( secret_dict_vars ) , _test_constants._single_taint_error_true)
        graph.var_tracker_list.clear()        

    def testUnameTypeInTaintDict(self):            
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._single_taint_script_name ) 
        _, secret_dict_vars =  orchestra.finalizeHardCodedSecrets( dict_all_attr, dict_all_vari )  
        self.assertTrue( getTypeFromSmellDict( secret_dict_vars ) ,  _test_constants._single_taint_error_msg ) 
        graph.var_tracker_list.clear()

    def testUnameTaintDict(self):            
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._single_taint_script_name ) 
        _, secret_dict_vars =  orchestra.finalizeHardCodedSecrets( dict_all_attr, dict_all_vari )  
        secret_taint_dict = graph.trackTaint( _test_constants.OUTPUT_SECRET_KW, secret_dict_vars, dict_all_attr, dict_all_vari )
        self.assertTrue( _test_constants._single_taint_dict_key in  secret_taint_dict , _test_constants._single_taint_error_true)        
        graph.var_tracker_list.clear()        

    def testTaintedHTTP_V1(self):            
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._taintedHttp_script_v1 ) 
        _, http_dict_vars =  orchestra.finalizeHTTP( dict_all_attr, dict_all_vari ) 
        http_taint_dict = graph.trackTaint( _test_constants.OUTPUT_HTTP_KW, http_dict_vars, dict_all_attr, dict_all_vari )
        self.assertEqual( 3 , len(http_taint_dict['$magnum_protocol']) , _test_constants._tainted_http_msg_v1)         
        graph.var_tracker_list.clear()        


    def testTaintedHTTP_V2(self):            
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._taintedHttp_script_v2 ) 
        _, http_dict_vars =  orchestra.finalizeHTTP( dict_all_attr, dict_all_vari )  
        http_taint_dict = graph.trackTaint( _test_constants.OUTPUT_HTTP_KW, http_dict_vars, dict_all_attr, dict_all_vari )
        self.assertEqual( 6 , len(http_taint_dict['$manila_protocol']) , _test_constants._tainted_http_msg_v2)         
        graph.var_tracker_list.clear()        

    def testTaintedHTTP_V3(self):            
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._taintedHttp_script_v3 ) 
        _, http_dict_vars =  orchestra.finalizeHTTP( dict_all_attr, dict_all_vari )  
        http_taint_dict = graph.trackTaint( _test_constants.OUTPUT_HTTP_KW, http_dict_vars, dict_all_attr, dict_all_vari )
        self.assertEqual( 9 , len(http_taint_dict['$cinder_protocol']) , _test_constants._tainted_http_msg_v3)         
        graph.var_tracker_list.clear()                

    def testTaintedHTTP_V4(self):           
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._taintedHttp_script_v4 ) 
        _, http_dict_vars =  orchestra.finalizeHTTP( dict_all_attr, dict_all_vari )  
        http_taint_dict = graph.trackTaint( _test_constants.OUTPUT_HTTP_KW, http_dict_vars, dict_all_attr, dict_all_vari )
        self.assertEqual( 1 , len(http_taint_dict['http_scheme']) , _test_constants._tainted_http_msg_v4 )         
        graph.var_tracker_list.clear()                

    def testTaintedHTTP_V5(self):            
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._taintedHttp_script_v5 ) 
        _, http_dict_vars =  orchestra.finalizeHTTP( dict_all_attr, dict_all_vari )  
        http_taint_dict = graph.trackTaint( _test_constants.OUTPUT_HTTP_KW, http_dict_vars, dict_all_attr, dict_all_vari )
        self.assertEqual( 1 , len(http_taint_dict['http_scheme']) , _test_constants._tainted_http_msg_v5 )         
        graph.var_tracker_list.clear()                        

    def testTaintedHopCountV1(self):            
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._multi_taint_script_name ) 
        _, http_dict_vars =  orchestra.finalizeHTTP( dict_all_attr, dict_all_vari )  
        http_taint_dict = graph.trackTaint( _test_constants.OUTPUT_HTTP_KW, http_dict_vars, dict_all_attr, dict_all_vari )
        self.assertEqual( 2 , http_taint_dict['$dashboard_link'][0][-1] , _test_constants.common_error_string + str(2) )         
        graph.var_tracker_list.clear()                

    def testTaintedHopCountV2(self):            
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._taintedHttp_script_v3 ) 
        _, http_dict_vars =  orchestra.finalizeHTTP( dict_all_attr, dict_all_vari )  
        http_taint_dict = graph.trackTaint( _test_constants.OUTPUT_HTTP_KW, http_dict_vars, dict_all_attr, dict_all_vari )
        self.assertEqual( 1 , http_taint_dict['$cinder_protocol'][0][-1] , _test_constants.common_error_string + str(1) )         
        graph.var_tracker_list.clear()                

    def testTaintedDefaultAdminV1(self):            
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._default_adm_script_name ) 
        default_admin_dict                          = orchestra.finalizeDefaults( dict_all_vari )
        _, secret_dict_vars                         = orchestra.finalizeHardCodedSecrets( dict_all_attr, dict_all_vari )
        secret_taint_dict                           = graph.trackTaint( constants.OUTPUT_SECRET_KW, secret_dict_vars, dict_all_attr, dict_all_vari )
        default_taint_dict                          = orchestra.getTaintAdminDict( default_admin_dict, secret_taint_dict  )        
        self.assertEqual( 1 , len(default_taint_dict) , _test_constants.common_error_string + str(1) ) 
        graph.var_tracker_list.clear()               

    def testTaintedWeakCryptoV1(self):                    
        _, _, dict_all_attr, dict_all_vari, _, _, dict_func = parser.executeParser( _test_constants._weak_cryp_script_name ) 
        weak_crypt_dic     =  orchestra.finalizeWeakEncrypt( dict_func ) 
        weak_cry_dic_taint =  orchestra.getTaintWeakCryptDict( weak_crypt_dic, dict_all_attr, dict_all_vari )
        self.assertEqual( 2 , len(weak_cry_dic_taint) , _test_constants.common_error_string + str(2) )  
        graph.var_tracker_list.clear()               

    def testTaintedWeakCryptoV2(self):      
        _, _, dict_all_attr, dict_all_vari, _, _, dict_func = parser.executeParser( _test_constants._empty_pass_script_name ) 
        weak_crypt_dic     =  orchestra.finalizeWeakEncrypt( dict_func ) 
        weak_cry_dic_taint =  orchestra.getTaintWeakCryptDict( weak_crypt_dic, dict_all_attr, dict_all_vari )
        self.assertEqual( 0 , len(weak_cry_dic_taint) , _test_constants.common_error_string + str(0) )  
        graph.var_tracker_list.clear()               

    def testTaintedWeakCryptoV3(self):                    
        _, _, dict_all_attr, dict_all_vari, _, _, dict_func = parser.executeParser( _test_constants._weak_crypt_script ) 
        weak_crypt_dic     =  orchestra.finalizeWeakEncrypt( dict_func ) 
        weak_cry_dic_taint =  orchestra.getTaintWeakCryptDict( weak_crypt_dic, dict_all_attr, dict_all_vari )
        self.assertEqual( 1 , len(weak_cry_dic_taint) , _test_constants.common_error_string + str(1) )         
        graph.var_tracker_list.clear()               

    def testTaintedEmptyPass(self):                    
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._tainted_empty_pass_script ) 
        _, empty_pwd_vars = orchestra.finalizeEmptyPassword( dict_all_attr, dict_all_vari  )
        empty_pwd_taint_dict           = graph.trackTaint( constants.OUTPUT_EMPTY_KW, empty_pwd_vars, dict_all_attr, dict_all_vari )        
        self.assertEqual( 0 , len(empty_pwd_taint_dict) , _test_constants.common_error_string + str(0) )         
        graph.var_tracker_list.clear()               

    def testTaintedPassword(self):                    
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._tainted_pass_script ) 
        secret_dict_attr, secret_dict_vars = orchestra.finalizeHardCodedSecrets( dict_all_attr, dict_all_vari )
        secret_taint_dict                  = graph.trackTaint( constants.OUTPUT_SECRET_KW, secret_dict_vars, dict_all_attr, dict_all_vari )
        self.assertEqual( 2 , len(secret_taint_dict) + len(secret_dict_attr) , _test_constants.common_error_string + str(2) )         
        graph.var_tracker_list.clear()               

def checkVarInSmellDict(  dic_smell  ):
        status = False
        for var_cnt, var_data in dic_smell.items():
            name, value, type_ = var_data
            if ( name == _test_constants._single_taint_var ): 
                status = True 
        return status 

def getTypeFromSmellDict( dic_smell ):
        status = False
        for var_cnt, var_data in dic_smell.items():
            name, value, type_ = var_data
            if ( type_ == _test_constants._single_taint_type ): 
                status = True 
        return status 

if __name__ == '__main__':
    unittest.main()
