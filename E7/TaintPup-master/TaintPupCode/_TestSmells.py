import unittest 
import _test_constants
import parser 
import orchestra 

class TestSmells( unittest.TestCase ):

    def testSuspiciousCommentV1( self ): 
        susp_ls = parser.getSuspComments( _test_constants._susp_script_1 )
        self.assertEqual(  0 , len(susp_ls) , _test_constants.common_error_string + str(0) ) 


    def testSuspiciousCommentV2( self ): 
        susp_ls = parser.getSuspComments( _test_constants._susp_script_2 )
        self.assertEqual(  5 , len(susp_ls) , _test_constants._susp_error_msg) 

    def testSuspiciousCommentV3( self ): 
        susp_ls = parser.getSuspComments( _test_constants._missing_default_script_name )
        self.assertEqual(  6 , len(susp_ls) , _test_constants.common_error_string + str(6) ) 

    def testMissingDefaultPresenceV1( self ): 
        _, _, _, _, dict_switch, _, _ = parser.executeParser( _test_constants._missing_default_script_name ) 
        no_default_count = orchestra.finalizeSwitches( dict_switch )
        self.assertEqual(  1 , no_default_count , _test_constants._missing_default_msg) 

    def testMissingDefaultPresenceV2( self ): 
        _, _, _, _, dict_switch, _, _ = parser.executeParser( _test_constants._missing_default_script2 ) 
        no_default_count = orchestra.finalizeSwitches( dict_switch  )
        self.assertEqual(  1 , no_default_count , _test_constants.common_error_string + str (1) ) 

    def testMissingDefaultPresenceV3( self ): 
        _, _, _, _, dict_switch, _, _ = parser.executeParser( _test_constants._missing_default_script3 ) 
        no_default_count = orchestra.finalizeSwitches( dict_switch  )
        self.assertEqual(  0 , no_default_count , _test_constants.common_error_string + str (0) ) 

    def testMissingDefaultPresenceV4( self ): 
        _, _, _, _, dict_switch, _, _ = parser.executeParser( _test_constants._missing_default_script4 ) 
        no_default_count = orchestra.finalizeSwitches( dict_switch  )
        self.assertEqual(  1 , no_default_count , _test_constants.common_error_string + str (1) ) 

    def testMissingDefaultPresenceV5( self ): 
        _, _, _, _, dict_switch, _, _ = parser.executeParser( _test_constants._missing_default_script5 ) 
        no_default_count = orchestra.finalizeSwitches( dict_switch  )
        self.assertEqual(  1 , no_default_count , _test_constants.common_error_string + str (1) ) 

    def testMissingDefaultPresenceV6( self ): 
        _, _, _, _, dict_switch, _, _ = parser.executeParser( _test_constants._missing_default_script6 ) 
        no_default_count = orchestra.finalizeSwitches( dict_switch  )
        self.assertEqual(  0 , no_default_count , _test_constants.common_error_string + str (0) ) 

    def testMissingDefaultPresenceV7( self ): 
        _, _, _, _, dict_switch, _, _ = parser.executeParser( _test_constants._missing_default_script7 ) 
        no_default_count = orchestra.finalizeSwitches( dict_switch  )
        self.assertEqual(  0 , no_default_count , _test_constants.common_error_string + str (0) ) 

    def testMissingDefaultPresenceV8( self ): 
        _, _, _, _, dict_switch, _, _ = parser.executeParser( _test_constants._missing_default_script8 ) 
        default_count = orchestra.finalizeSwitches( dict_switch  )
        self.assertEqual(  0 , default_count , _test_constants.common_error_string + str (0) ) 

    def testMissingDefaultPresenceV9( self ): 
        _, _, _, _, dict_switch, _, _ = parser.executeParser( _test_constants._missing_default_script9 ) # this one has a default block 
        default_count = orchestra.finalizeSwitches( dict_switch  )
        self.assertEqual(  0 , default_count , _test_constants.common_error_string + str (0) ) 

    def testMissingDefaultPresenceV10( self ): 
        _, _, _, _, dict_switch, _, _ = parser.executeParser( _test_constants._missing_default_script10 ) # this one has a default block 
        default_count = orchestra.finalizeSwitches( dict_switch  )
        self.assertEqual(  0 , default_count , _test_constants.common_error_string + str (0) ) 


    def testMissingDefaultPresenceV11( self ): 
        _, _, _, _, dict_switch, _, _ = parser.executeParser( _test_constants._missing_default_script11 ) # this one has a default block 
        default_count = orchestra.finalizeSwitches( dict_switch  )
        self.assertEqual(  0 , default_count , _test_constants.common_error_string + str (0) ) 

    def testPresentDefault( self ): 
        _, _, _, _, dict_switch, _, _ = parser.executeParser( _test_constants._present_default_script_name ) 
        no_default_count = orchestra.finalizeSwitches( dict_switch  )
        self.assertEqual(  0 , no_default_count , _test_constants._present_default_msg) 


    def testInavlidIPPresence( self ): 
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._invalid_ip_script_name1 ) 
        ip_attr, ip_vars = orchestra.finalizeInvalidIPs( dict_all_attr, dict_all_vari )
        self.assertEqual(  0 , len(ip_attr) , _test_constants._invalid_ip_msg0 ) 
        self.assertEqual(  1 , len(ip_vars) , _test_constants._invalid_ip_msg1 ) 

    def testInavlidIPAbsence( self ): 
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._invalid_ip_script_name3 ) 
        ip_attr, ip_vars = orchestra.finalizeInvalidIPs( dict_all_attr, dict_all_vari )
        self.assertEqual(  0 , len(ip_vars) , _test_constants._invalid_ip_msg0 ) 
        self.assertEqual(  1 , len(ip_attr) , _test_constants._invalid_ip_msg1 ) 

    def testHTTPForVariables( self ): 
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._http_var_script_name ) 
        http_attr, http_vars = orchestra.finalizeHTTP( dict_all_attr, dict_all_vari )
        self.assertEqual(  3 , len(http_vars) , _test_constants._http_msg_1 ) 
        self.assertEqual(  0 , len(http_attr) , _test_constants._http_msg_0 )  

    def testHTTPForAttributes( self ): 
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._http_attr_script_name ) 
        http_attr, http_vars = orchestra.finalizeHTTP( dict_all_attr, dict_all_vari )
        self.assertEqual(  1 , len(http_vars) , _test_constants._http_msg_1 ) 
        self.assertEqual(  1 , len(http_attr) , _test_constants._http_msg_1 )  

    def testWeakCrypto( self ): 
        _, _, _, _, _, _, dict_func = parser.executeParser( _test_constants._weak_cryp_script_name ) 
        dict_ = orchestra.finalizeWeakEncrypt( dict_func )
        self.assertEqual(  3 , len(dict_) , _test_constants._weak_cryp_msg_ ) 

    def testEmptyPasswordForVariables( self ): 
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._empty_pass_script_name ) 
        _attr, _vars = orchestra.finalizeEmptyPassword( dict_all_attr, dict_all_vari )
        self.assertEqual(  1 , len(  _vars ) , _test_constants._empty_pass_msg_ ) 

    def testDefaultAdmin( self ): 
        _, _, _, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._default_adm_script_name ) 
        _vars = orchestra.finalizeDefaults(  dict_all_vari )
        self.assertEqual(  1 , len(  _vars ) , _test_constants._default_adm_msg_ ) 

    def testHardcodedUser( self ): 
        self.assertTrue( orchestra.isValidUserName( _test_constants._secret_uname ) , _test_constants._secret_flag_status  ) 

    def testHardcodedPass( self ): 
        self.assertTrue( orchestra.isValidPasswordName( _test_constants._secret_password ) , _test_constants._secret_flag_status  ) 

    def testHardcodedSecretV1( self ): 
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._secret_script_name ) 
        _attr, _vars = orchestra.finalizeHardCodedSecrets( dict_all_attr, dict_all_vari )
        self.assertEqual(  2 , len(  _vars ) , _test_constants._secret_msg_ ) 

    def testHardcodedSecretV2( self ): 
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._secret_script_v2 )
        _attr, _vars = orchestra.finalizeHardCodedSecrets( dict_all_attr, dict_all_vari )
        self.assertEqual(  0 , len(  _attr ) , _test_constants._secret_msg_ ) 

    def testHardcodedSecretV3( self ): 
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._secret_script_v3 )
        _attr, _vars = orchestra.finalizeHardCodedSecrets( dict_all_attr, dict_all_vari )
        self.assertEqual(  0 , len(  _attr ) , _test_constants._secret_msg_ ) 

    def testHardcodedSecretV4( self ): 
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._secret_script_v3 )
        _attr, _vars = orchestra.finalizeHardCodedSecrets( dict_all_attr, dict_all_vari )
        self.assertEqual(  0 , len(  _vars ) , _test_constants._secret_msg_ ) 

    def testHardcodedSecretV5( self ): 
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._secret_script_v4 )
        _attr, _vars = orchestra.finalizeHardCodedSecrets( dict_all_attr, dict_all_vari )
        self.assertEqual(  8 , len(  _attr ) , _test_constants._secret_msg_ ) 

    def testHardcodedSecretV6( self ): 
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._secret_script_v5 )
        _attr, _vars = orchestra.finalizeHardCodedSecrets( dict_all_attr, dict_all_vari )
        self.assertEqual(  5 , len(  _attr ) , _test_constants._secret_msg_ ) 

    def testHardcodedSecretV7( self ): 
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._secret_script_v6 )
        _attr, _vars = orchestra.finalizeHardCodedSecrets( dict_all_attr, dict_all_vari )
        self.assertEqual(  14 , len(  _attr ) , _test_constants._secret_msg_ ) 

    def testHardcodedSecretV8( self ): 
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._secret_script_v7 )
        _attr, _vars = orchestra.finalizeHardCodedSecrets( dict_all_attr, dict_all_vari )
        self.assertEqual(  10 , len(  _attr ) , _test_constants._secret_msg_ ) 

    def testHardcodedUname( self ): 
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._username_script_name ) 
        _attr, _vars = orchestra.finalizeHardCodedSecrets( dict_all_attr, dict_all_vari )
        self.assertEqual(  2 , len(  _attr ), _test_constants._secret_msg_ ) 

    def testExampleDomainHTTP( self ): 
        self.assertTrue( orchestra.extraHTTPCheck( _test_constants._example_domain_str ) , _test_constants.common_error_string + str(True)   )

    def testHardcodedSecretV9( self ): 
        _, _, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( _test_constants._secret_strange_config_script )
        _attr, _vars = orchestra.finalizeHardCodedSecrets( dict_all_attr, dict_all_vari )
        self.assertEqual(  2 , len(  _attr ) , _test_constants.common_error_string + str(2) ) 


if __name__ == '__main__':
    unittest.main()