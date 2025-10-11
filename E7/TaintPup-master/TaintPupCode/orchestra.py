'''
Akond Rahman 
Dec 09, 2020
Orchestrate parser and graph generator 
'''

import constants 
import  parser 
import os 
from collections import Counter 
import graph 
import requests 
import time 
import  datetime 
import pandas as pd 

def giveTimeStamp():
  tsObj = time.time()
  strToret = datetime.datetime.fromtimestamp(tsObj).strftime(constants.TIME_FORMAT) 
  return strToret

def getPuppetFiles(path_to_dir):
    valid_  = [] 
    for root_, dirs, files_ in os.walk( path_to_dir ):
       for file_ in files_:
           full_p_file = os.path.join(root_, file_)
           if(os.path.exists(full_p_file)):
             if (full_p_file.endswith( constants.PP_EXTENSION  )):
               valid_.append(full_p_file)
    return valid_ 

def finalizeSusps(ls):
    return len(ls) 

def finalizeSwitches( dic_ ): 
    no_default_count = 0 
    prior_case_branch = constants.NULL_SYMBOL
    for k_, v_ in dic_.items():
        branches = v_[-1]
        # print(k_) 
        # print(branches) 
        per_case_branch = constants.NULL_SYMBOL
        default_flag = False 
        for branch_count, branch_content in branches.items():
            branch_name = branch_content[-1]
            per_case_branch = per_case_branch +  constants.EQUAL_SYMBOL +  branch_name
            if constants.CASE_DEFAULT_KEYWORD in branch_name:
                    default_flag = True                 
        if default_flag == False and prior_case_branch != per_case_branch  : 
            no_default_count += 1 
        prior_case_branch = per_case_branch 
        # print(prior_case_branch, per_case_branch) 
    return no_default_count


def sanitizeConfigVals(config_data):
    valid_config_data = constants.VALID_CONFIG_DEFAULT 
    if(constants.IP_ADDRESS_PATTERN in config_data) and (constants.YUM_KW not in config_data) :
        valid_config_data = config_data.replace(constants.QUOTE_SYMBOL, constants.NULL_SYMBOL)
    elif(  constants.HTTP_PATTERN in config_data ):
        valid_config_data = config_data.replace(constants.WHITESPACE_SYMBOL, constants.NULL_SYMBOL)
    elif(  constants.XTRA_HTTP_PATTERN in config_data ):
        valid_config_data = config_data.replace(constants.WHITESPACE_SYMBOL, constants.NULL_SYMBOL)
    data_value =  valid_config_data.strip() 
    data_ascii = sum([ ord(y_) for y_ in data_value ])     
    return data_ascii

def finalizeInvalidIPs(attr_dict, dict_vars):
    output_attrib_dict, output_variable_dict = {}, {}
    attr_count , var_count = 0 , 0
    for attr_key, attr_data in attr_dict.items():
        attr_count += 1 
        attr_name  = attr_data[-2] 
        attr_value = attr_data[-1]
        attr_ascii = sanitizeConfigVals( attr_value )
        if attr_ascii == 330 or attr_ascii == 425: # 330 is the total of '0.0.0.0', 425  is the total of '0.0.0.0/0'
            output_attrib_dict[attr_count] = (attr_name, attr_value, attr_ascii)  # keeping ascii for debugging in taint tracking 
    for var_name, var_data in dict_vars.items():
        var_count += 1 
        var_value = var_data[-1]
        var_ascii = sanitizeConfigVals( var_value )
        if var_ascii == 330 or var_ascii == 425:  
            output_variable_dict[var_count] = (var_name, var_value, var_ascii) 
    return  output_attrib_dict, output_variable_dict # dict will help in taint tracking 

def extraHTTPCheck(_valu):
    flag_ = True
    if(constants.LOCALHOST_KEYWORD in _valu) or (constants.CONCAT_KEYWORD in _valu) or ( constants.LOCAL_IP_KEYWORD in _valu ) or ( constants.DOLLAR_SYMBOL in _valu) or ( constants.EXAMPLE_DOMAIN_KEYWORD in _valu ) :
        flag_ = True 
    # elif ( any(z_ in _valu for z_ in constants.INVALID_HTTP_PATTERNS) ):
    #     flag_ = False 
    else: 
        third_slash_loc, cnt  = 0 , 0
        for z in range( len(_valu) ):
            if _valu[z] == constants.SLASH_SYMBOL :
                cnt += 1 
            if cnt == 3: 
                third_slash_loc = z 
        url_string = _valu[0:z]
        url_list   = url_string.split(constants.COLON_SYMBOL)
        http_part  = url_list[0] + constants.AN_S + constants.COLON_SYMBOL
        url_string = http_part + constants.NULL_SYMBOL.join( url_list[1:] )
        try:
            r = requests.head( url_string  ) 
            if r.status_code < 400:
                flag_ = True 
        except Exception as e_:
            flag_ = False 

    return flag_

def finalizeHTTP(attr_dict, dict_vars):
    attr_count , var_count = 0 , 0
    output_attrib_dict, output_variable_dict = {}, {}
    for attr_key, attr_data in attr_dict.items():
        attr_count += 1 
        attr_name  = attr_data[-2] 
        attr_value = attr_data[-1]
        attr_ascii = sanitizeConfigVals( attr_value )
        if (attr_ascii >= 600) and ( constants.HTTP_PATTERN in attr_value) and (extraHTTPCheck( attr_value ) ): # 600 is the total of 'http://'
            # print( attr_value, extraHTTPCheck( attr_value ) )
            output_attrib_dict[attr_count] = ( attr_name, attr_value, attr_ascii)  # keeping ascii for debugging in taint tracking 
    for var_name, var_data in dict_vars.items():
        var_count += 1 
        var_value = var_data[-1]
        var_ascii = sanitizeConfigVals( var_value )
        # print( var_name, var_data,  var_ascii) 
        if (var_ascii >= 600) and ( constants.HTTP_PATTERN in var_value) and (extraHTTPCheck( var_value) ): # 600 is the total of 'http://'
            output_variable_dict[var_count] = (var_name, var_value, var_ascii) 
        elif ( any( z in var_name for z in constants.XTRA_HTTP_VAR_KWS) ) and  (var_ascii ==  448 or var_ascii == 526) : ### need to handle $magnum_protocol = 'http', ascii for 'http' is 448
            output_variable_dict[var_count] = ( var_name, var_value, var_ascii)                     


    # print( output_variable_dict ) 
    return output_attrib_dict, output_variable_dict # dict will help in taint tracking 

def finalizeWeakEncrypt(func_dict):
    weak_count  = 0 
    weak_dict   = {}
    for func_count, func_data in func_dict.items():
        func_assignee = func_data[0]
        func_name     = func_data[1] 
        func_params   = func_data[2] 
        if constants.MD5_KEYWORD in func_name: 
            weak_count += 1 
            weak_dict[weak_count] = func_assignee,  func_name , func_params,  constants.MD5_KEYWORD            
        elif  constants.SHA1_KEYWORD in func_name:
            weak_count += 1 
            weak_dict[weak_count] =  func_assignee,  func_name, func_params,  constants.SHA1_KEYWORD
    return weak_dict

def checkIfValidSecret(single_config_val):
    flag2Ret = False 
    config_val = single_config_val.strip() 
    if ( any(x_ in config_val for x_ in constants.INVALID_SECRET_CONFIG_VALUES ) ):
        flag2Ret = False 
    else:
        if(  len(config_val) > 2 ) and ( constants.QUOTE_SYMBOL in config_val ) :
            flag2Ret = True 
    return flag2Ret

def checkIfEmptyPass(single_config_val):
    flag2Ret = False 
    if ( any(x_ in single_config_val for x_ in constants.INVALID_SECRET_CONFIG_VALUES ) ):
        flag2Ret = False 
    else:
        single_config_val = single_config_val.strip() 
        if(  len(single_config_val) == 2 ) and ( constants.QUOTE_SYMBOL in single_config_val ) : ## we want to detect stuff like $password = ''
            flag2Ret = True 
    return flag2Ret

def isValidUserName(uName): 
    valid = True
    if( any(z_ in uName for z_ in constants.FORBIDDEN_USER_NAMES ) ): 
        valid = False  
    return valid

def isValidKeyName(keyName): 
    valid = True
    if( any(z_ in keyName for z_ in constants.FORBIDDEN_KEY_NAMES ) ): 
        valid = False  
    return valid

def isValidPasswordName(pName): 
    valid = True
    if( any(z_ in pName for z_ in constants.FORBIDDEN_PASS_NAMES) ): 
        valid = False  
    return valid
  

def finalizeHardCodedSecrets( attr_dict, vars_dict ):
    secret_attr_dict , secret_var_dict = {}, {} 
    attr_count , var_count = 0 , 0
    for attr_key, attr_data in attr_dict.items():
        attr_count += 1 
        attr_name  = attr_data[-2] 
        attr_value = attr_data[-1]
        attr_name  = attr_name.strip() 
        if(any(x_ in attr_name for x_ in constants.SECRET_PASSWORD_LIST )) and (checkIfValidSecret ( attr_value ) ) and (isValidPasswordName( attr_name )):        
            secret_attr_dict[attr_count] = attr_name,   attr_value, constants.OUTPUT_PASS_KW
        elif(any(x_ in attr_name for x_ in constants.SECRET_USER_LIST )) and (checkIfValidSecret ( attr_value ) ) and (isValidUserName( attr_name ) ) :        
            secret_attr_dict[attr_count] =  attr_name,  attr_value, constants.OUTPUT_USER_KW
        elif(any(x_ in attr_name for x_ in constants.SECRET_KEY_LIST )) and (checkIfValidSecret ( attr_value ) ) and (isValidKeyName( attr_name ) ) :        
            secret_attr_dict[attr_count] =  attr_name,  attr_value , constants.OUTPUT_TOKEN_KW
    for var_name, var_data in vars_dict.items():
        var_count  += 1 
        var_value  = var_data[-1]
        var_name   = var_name.strip() 
        # print( var_name, var_value , isValidKeyName( var_name ) , checkIfValidSecret( var_value ) )
        if(any(x_ in var_name for x_ in constants.SECRET_PASSWORD_LIST )) and (checkIfValidSecret ( var_value ) ) and ( isValidPasswordName( var_name ) ):        
            secret_var_dict[var_count] = var_name, var_value, constants.OUTPUT_PASS_KW
        elif(any(x_ in var_name for x_ in constants.SECRET_USER_LIST )) and (checkIfValidSecret ( var_value ) ) and (isValidUserName( var_name ) ):        
            secret_var_dict[var_count] = var_name, var_value, constants.OUTPUT_USER_KW 
        elif(any(x_ in var_name for x_ in constants.SECRET_KEY_LIST )) and (checkIfValidSecret ( var_value ) ) and (isValidKeyName( var_name ) ) :        
            secret_var_dict[var_count] = var_name, var_value, constants.OUTPUT_TOKEN_KW
    return secret_attr_dict, secret_var_dict  

def finalizeEmptyPassword( attr_dict, vars_dict ):
    empty_attr_dict , empty_var_dict = {}, {} 
    attr_count , var_count = 0 , 0
    for attr_key, attr_data in attr_dict.items():
        attr_count += 1 
        attr_name  = attr_data[-2] 
        attr_value = attr_data[-1]
        attr_name  = attr_name.strip() 
        if(any(x_ in attr_name for x_ in constants.SECRET_PASSWORD_LIST )) and (checkIfEmptyPass ( attr_value ) ) and (isValidPasswordName( attr_name )) :        
            empty_attr_dict[attr_count] = attr_name,   attr_value, constants.OUTPUT_EMPTY_KW
    for var_name, var_data in vars_dict.items():
        var_count += 1 
        var_value  = var_data[-1]
        var_name   = var_name.strip() 
        if(any(x_ in var_name for x_ in constants.SECRET_PASSWORD_LIST )) and (checkIfEmptyPass ( var_value ) ) and (isValidPasswordName( var_name )) :         
            empty_var_dict[var_count] = var_name,  var_value, constants.OUTPUT_EMPTY_KW
    return empty_attr_dict, empty_var_dict  

def checkIfAdmin(single_config_val):
    flag2Ret = False 
    if ( any(x_ in single_config_val for x_ in constants.INVALID_SECRET_CONFIG_VALUES ) ):
        flag2Ret = False 
    else:
        if(  len(single_config_val) > 0 ) and ( constants.QUOTE_SYMBOL in single_config_val )  and ( constants.ADMIN_KEYWORD in single_config_val) : 
            flag2Ret = True 
    return flag2Ret

def finalizeDefaults( vars_dict ):
    default_var_dict = {} 
    var_cnt  = 0 
    for var_name, var_data in vars_dict.items():
        var_cnt += 1 
        var_value  = var_data[-1]
        var_name   = var_name.strip() 
        if(any(x_ in var_name for x_ in constants.SECRET_USER_LIST )) and (checkIfAdmin ( var_value ) ):        
            default_var_dict[var_cnt] =  var_name, var_value, constants.OUTPUT_DEFAULT_ADMIN_KW 
    return default_var_dict      

def orchestrateWithoutTaint(dir_):
    all_pupp_files = getPuppetFiles(  dir_ )
    for pupp_file in all_pupp_files:
        dict_reso, dict_clas, dict_all_attr, dict_all_vari, dict_switch, list_susp_comm, dict_func = parser.executeParser( pupp_file ) 

        susp_cnt       = finalizeSusps( list_susp_comm )
        switch_cnt     = finalizeSwitches( dict_switch )
        weak_crypt_dic = finalizeWeakEncrypt( dict_func ) 
        default_admin_dict   = finalizeDefaults( dict_all_vari )

        invalid_ip_dict_attr, invalid_ip_dict_vars  = finalizeInvalidIPs( dict_all_attr, dict_all_vari ) 
        tot_invalid_ip_cnt = len(invalid_ip_dict_attr) + len(invalid_ip_dict_vars)

        http_dict_attr, http_dict_vars = finalizeHTTP( dict_all_attr, dict_all_vari )
        tot_http_cnt = len(http_dict_attr) + len(http_dict_vars)

        
        secret_dict_attr, secret_dict_vars = finalizeHardCodedSecrets( dict_all_attr, dict_all_vari )
        total_secret_count = len(secret_dict_attr) + len(secret_dict_vars) 
        
        empty_pwd_attr, empty_pwd_vars = finalizeEmptyPassword( dict_all_attr, dict_all_vari  )
        tot_empty_pass_count = len( empty_pwd_attr ) + len(empty_pwd_vars)


        print( pupp_file, susp_cnt, switch_cnt , tot_invalid_ip_cnt, tot_http_cnt, len(weak_crypt_dic )  , total_secret_count , tot_empty_pass_count , len(default_admin_dict ) )
        print('-'*100)


def getReferredScriptName(cls_name, module_name):
    reff_script_path = constants.NULL_SYMBOL 
    cls_name = cls_name.replace( constants.RESOURCE_KEYWORD , constants.NULL_SYMBOL)
    cls_name = cls_name.replace( constants.LPAREN_SYMBOL , constants.NULL_SYMBOL)
    cls_name = cls_name.replace( constants.NEWLINE_CONSTANT , constants.NULL_SYMBOL)
    cls_name = cls_name.replace( constants.WHITESPACE_SYMBOL , constants.NULL_SYMBOL)
    cls_name = cls_name.replace( constants.QUOTE_SYMBOL , constants.NULL_SYMBOL)
    if cls_name.replace( constants.COLON_SYMBOL * 2, constants.NULL_SYMBOL ) == module_name:
        reff_script_path = constants.INIT_FILE_KW 
    else:
        splitted_list = cls_name.split( constants.COLON_SYMBOL * 2  )  ## synatx is ::<module_name>::script
        splitted_list = [z_ for z_ in splitted_list if len(z_) > 0  and z_ != module_name ]
        # print(cls_name)
        # print(splitted_list) 
        reff_script_path = constants.SLASH_SYMBOL.join( splitted_list )
        # print( reff_script_path )
        # print('='*50)

    return  reff_script_path 


def getReferredScripts( class_dic , script_path): 
    scripts2track      = []
    script_module_path = script_path.replace( constants._DATASET_PATH ,  constants.NULL_SYMBOL )
    script_module_name = script_module_path.split( constants.SLASH_SYMBOL )[0] 
    script_module_name = script_module_name.replace( constants.PUPPET_KW, constants.NULL_SYMBOL )
    script_module_name = script_module_name.replace( constants.MONTH_DATA_KW, constants.NULL_SYMBOL ) 
    for class_index, class_data in class_dic.items(): 
        class_attrs = class_data[-1] 
        class_name  = class_data[0]
        if constants.COLON_SYMBOL * 2 in class_name:
            reff_path =getReferredScriptName( class_name, script_module_name )
            full_script_path = constants._DATASET_PATH + constants.PUPPET_KW + script_module_name + constants.MONTH_DATA_KW + constants.SLASH_SYMBOL + constants.MANIFESTS_KW + constants.SLASH_SYMBOL  + reff_path + constants.PP_EXTENSION
            # print( full_script_path )
            if  os.path.exists( full_script_path ) : 
                scripts2track.append(  (class_index, full_script_path  )  )

    return scripts2track
    


def checkAttribInReferred( name2check, dict_vari ):
    checkFlag = False
    for k_, v_ in dict_vari.items(): 
        if name2check in k_ : 
            checkFlag = True 
    return checkFlag


def getCrossScriptSecret( script_list, class_dict ):
    output_count, output_dict = 0, {}
    for tup_ in script_list:
        class_index, refferred_full_path = tup_
        if class_index in class_dict: 
            attr_dict = class_dict[class_index][-1]
            for k_, v_ in attr_dict.items(): 
                attrib_name, attrib_value = v_[-2], v_[-1] 
                secret_attr_dict = {}
                if(any(x_ in attrib_name for x_ in constants.SECRET_PASSWORD_LIST )) and (checkIfValidSecret ( attrib_value ) ) and (isValidPasswordName ( attrib_name )):        
                    secret_attr_dict[attrib_name] =     constants.OUTPUT_PASS_KW
                elif(any(x_ in attrib_name for x_ in constants.SECRET_USER_LIST )) and (checkIfValidSecret ( attrib_value ) ) and (isValidUserName( attrib_name ) ) :        
                    secret_attr_dict[attrib_name] =    constants.OUTPUT_USER_KW
                elif(any(x_ in attrib_name for x_ in constants.SECRET_KEY_LIST )) and (checkIfValidSecret ( attrib_value ) ) and (isValidKeyName( attrib_name ) ) :        
                    secret_attr_dict[attrib_name] =     constants.OUTPUT_TOKEN_KW

                if (len( secret_attr_dict ) ) > 0:
                    _, _, dict_all_attr, _, _, _, _ = parser.executeParser( refferred_full_path )
                    '''
                    due to parser limitiation directly check if variable used by attributes 
                    for this we cannot do mutli-level taint tracking 

                    check if the attrib_name (variable in a referred script) is used by an attribute by checking if 
                    attrib_name is used by an attribute 
                    '''
                    the_dict = graph.trackSingleVarTaintInAttrib( attrib_name, dict_all_attr  )
                    # print(attrib_name)
                    # print( the_dict )
                    # print('='*25)
                    if ( attrib_name in the_dict ) :
                        output_count += 1 
                        output_dict[output_count] = ( class_index, refferred_full_path, attrib_name, attrib_value, secret_attr_dict[attrib_name] )
    # print(output_dict)
    return output_dict 


def getCrossScriptInvalidIP( script_list, class_dict ):
    output_count, output_dict = 0, {}
    for tup_ in script_list:
        class_index, refferred_full_path = tup_
        if class_index in class_dict: 
            attr_dict = class_dict[class_index][-1]
            for k_, v_ in attr_dict.items(): 
                attrib_name, attrib_value = v_[-2], v_[-1] 
                result_attr_dict = {}
                attr_ascii = sanitizeConfigVals( attrib_value )
                if attr_ascii == 330 or attr_ascii == 425: 
                    result_attr_dict[attrib_name] = constants.OUTPUT_INVALID_IP_KW 
                if (len( result_attr_dict ) ) > 0:
                    _, _, dict_all_attr, _, _, _, _ = parser.executeParser( refferred_full_path )
                    the_dict = graph.trackSingleVarTaintInAttrib( attrib_name, dict_all_attr  )
                    if ( attrib_name in the_dict ) :
                        output_count += 1 
                        output_dict[output_count] = ( class_index, refferred_full_path, attrib_name, attrib_value, result_attr_dict[attrib_name] )
    
    return output_dict 


def getCrossScriptHTTP( script_list, class_dict ):
    output_count, output_dict = 0, {}
    for tup_ in script_list:
        class_index, refferred_full_path = tup_
        if class_index in class_dict: 
            attr_dict = class_dict[class_index][-1]
            for k_, v_ in attr_dict.items(): 
                attrib_name, attrib_value = v_[-2], v_[-1] 
                result_attr_dict = {}
                attr_ascii = sanitizeConfigVals( attrib_value )
                if (attr_ascii >= 600) and ( constants.HTTP_PATTERN in attrib_value) and (extraHTTPCheck( attrib_value ) ): 
                    result_attr_dict[attrib_name] = constants.OUTPUT_HTTP_KW  
                if (len( result_attr_dict ) ) > 0:
                    _, _, dict_all_attr, _, _, _, _ = parser.executeParser( refferred_full_path )
                    the_dict = graph.trackSingleVarTaintInAttrib( attrib_name, dict_all_attr  )
                    if ( attrib_name in the_dict ) :
                        output_count += 1 
                        output_dict[output_count] = ( class_index, refferred_full_path, attrib_name, attrib_value, result_attr_dict[attrib_name] )
    return output_dict 


def getCrossScriptEmptyPass(script_list, class_dict):
    output_count, output_dict = 0, {}
    for tup_ in script_list:
        class_index, refferred_full_path = tup_
        if class_index in class_dict: 
            attr_dict = class_dict[class_index][-1]
            for k_, v_ in attr_dict.items(): 
                attrib_name, attrib_value = v_[-2], v_[-1] 
                result_attr_dict = {} 
                if(any(x_ in attrib_name for x_ in constants.SECRET_PASSWORD_LIST )) and (checkIfEmptyPass ( attrib_value ) ):        
                    result_attr_dict[attrib_name] = constants.OUTPUT_EMPTY_KW 
                if (len( result_attr_dict ) ) > 0:
                    _, _, dict_all_attr, _, _, _, _ = parser.executeParser( refferred_full_path )
                    the_dict = graph.trackSingleVarTaintInAttrib( attrib_name, dict_all_attr  )
                    if ( attrib_name in the_dict ) :
                        output_count += 1 
                        output_dict[output_count] = ( class_index, refferred_full_path, attrib_name, attrib_value, result_attr_dict[attrib_name] )
    # print(output_dict)
    return output_dict 


def getTaintAdminDict( dflt_dict, secret_taint_dict ):
    '''
    As default admin is a variant of a hard-coded user name , we will leverage 
    tainted secret dict to see if the default admin is actually in use 
    '''
    final_output_dic = {}
    for _, default_details in dflt_dict.items():
        var_name, var_value, constants.OUTPUT_DEFAULT_ADMIN_KW = default_details
        for k_, _ in secret_taint_dict.items():
            if (var_name == k_): 
                if var_name not in final_output_dic:
                    final_output_dic[var_name] = [(var_name, var_value ) ] 
                else: 
                    final_output_dic[var_name] = final_output_dic[var_name] + [ (var_name, var_value )  ]
    return final_output_dic 

def checkAtrribInDict( attrib_name_param, attrib_dict ):
    flag_ = False
    for k_, v_ in attrib_dict.items():
        _, _, attr_name, attr_val = v_ 
        attr_name = attr_name.strip()
        if (attrib_name_param in attr_name) or (attrib_name_param == attr_name): 
            flag_ = True  

    return flag_

def getTaintWeakCryptDict(weak_crypt_dic, dict_all_attr, dict_all_vari) :
    weak_cryp_assignee_dic = {}
    for count_, items_ in weak_crypt_dic.items():
        func_assignee, func_name, params , type_  = items_
        func_assignee     = func_assignee.replace( constants.LPAREN_SYMBOL, constants.NULL_SYMBOL ) 
        func_assignee     = func_assignee.replace( constants.WHITESPACE_SYMBOL, constants.NULL_SYMBOL ) 
        if ( checkAtrribInDict( func_assignee, dict_all_attr ) ):
            weak_cryp_assignee_dic[ func_assignee ] = [ ( func_name, type_ , func_assignee, 0 ) ]
        else: 
            taintedDic  = graph.trackSingleVarTaint( constants.OUTPUT_WEAK_ENCR_KW , func_assignee, dict_all_vari, dict_all_attr )
            for K_, V_ in taintedDic.items(): 
                for data_ in V_:
                    attr_name, attr_value , smell_type, hop_count = data_ 
                    if func_assignee not in weak_cryp_assignee_dic:
                        weak_cryp_assignee_dic[ func_assignee ] = [ (func_name, type_ , attr_name, hop_count) ]
                    else: 
                        weak_cryp_assignee_dic[ func_assignee ] =  weak_cryp_assignee_dic[ func_assignee ] +  [ ( func_name, type_ , attr_name, hop_count) ]
    return weak_cryp_assignee_dic 


def doFullTaintForSingleScript( pupp_file ): 
    dict_reso, dict_clas, dict_all_attr, dict_all_vari, dict_switch, list_susp_comm, dict_func = parser.executeParser( pupp_file ) 

    susp_cnt       = finalizeSusps( list_susp_comm )
    switch_cnt     = finalizeSwitches( dict_switch )


    invalid_ip_dict_attr, invalid_ip_dict_vars  = finalizeInvalidIPs( dict_all_attr, dict_all_vari ) 
    invalid_ip_taint_dict = graph.trackTaint( constants.OUTPUT_INVALID_IP_KW, invalid_ip_dict_vars, dict_all_attr, dict_all_vari )
    
    http_dict_attr, http_dict_vars = finalizeHTTP( dict_all_attr, dict_all_vari )
    http_taint_dict = graph.trackTaint( constants.OUTPUT_HTTP_KW, http_dict_vars, dict_all_attr, dict_all_vari )

    secret_dict_attr, secret_dict_vars = finalizeHardCodedSecrets( dict_all_attr, dict_all_vari )
    secret_taint_dict                  = graph.trackTaint( constants.OUTPUT_SECRET_KW, secret_dict_vars, dict_all_attr, dict_all_vari )

    empty_pwd_attr, empty_pwd_vars = finalizeEmptyPassword( dict_all_attr, dict_all_vari  )
    empty_pwd_taint_dict           = graph.trackTaint( constants.OUTPUT_EMPTY_KW, empty_pwd_vars, dict_all_attr, dict_all_vari )        

    default_admin_dict     = finalizeDefaults( dict_all_vari )
    default_taint_dict     = getTaintAdminDict( default_admin_dict, secret_taint_dict  )        


    weak_crypt_dic     = finalizeWeakEncrypt( dict_func ) 
    weak_cry_dic_taint = getTaintWeakCryptDict( weak_crypt_dic, dict_all_attr, dict_all_vari )

    '''
    cross script tracking zone 
    '''
    scripts2Track          = getReferredScripts( dict_clas , pupp_file ) 
    cross_secret_dict      = getCrossScriptSecret( scripts2Track, dict_clas )         
    cross_ip_dict          = getCrossScriptInvalidIP( scripts2Track, dict_clas ) 
    cross_http_dict        = getCrossScriptHTTP ( scripts2Track, dict_clas )     
    cross_empty_pass_dict  = getCrossScriptEmptyPass ( scripts2Track, dict_clas ) 

    secret_tuple           = ( secret_taint_dict, cross_secret_dict, secret_dict_attr, secret_dict_vars )
    ip_tuple               = ( invalid_ip_taint_dict, cross_ip_dict, invalid_ip_dict_attr, invalid_ip_dict_vars )
    http_tuple             = ( http_taint_dict, cross_http_dict, http_dict_attr, http_dict_vars ) 
    empty_pass_tuple       = ( empty_pwd_taint_dict, cross_empty_pass_dict, empty_pwd_attr, empty_pwd_vars ) 
    default_admin_tuple    = ( default_taint_dict, default_admin_dict )
    weak_cryp_tuple        = ( weak_cry_dic_taint, weak_crypt_dic  )    

    # print(  http_dict_vars, http_taint_dict )
    return ( susp_cnt, switch_cnt, ip_tuple, http_tuple, secret_tuple, empty_pass_tuple, default_admin_tuple, weak_cryp_tuple, dict_reso )


def mineProfileMetrics(pp_script):
    dict_reso, dict_clas, dict_all_attr, dict_all_vari, _, _, _ = parser.executeParser( pp_script ) 
    try:
        sloc = sum(1 for line in open(pp_script, encoding=constants.CSV_ENCODING ))
    except UnicodeDecodeError as err_:
        print( str( err_ ) )
        sloc = constants.NULL_CONSTANT

    return sloc, len(dict_reso), len(dict_clas), len(dict_all_attr), len(dict_all_vari) 

def orchestrateWithTaint(dir_):
    all_pupp_files = getPuppetFiles(  dir_ )
    final_res_dic  = {} 
    profile_data_holder = []
    for pupp_file in all_pupp_files:
        print( constants.ANALYZING_KW + pupp_file )
        start_    = time.monotonic()
        res_tup   = doFullTaintForSingleScript( pupp_file )
        end_      = time.monotonic()
        time_dura = round( ( end_ - start_ ), 5) 
        # loc, reso_cnt, clas_cnt, attr_cnt, vari_cnt = mineProfileMetrics( pupp_file )
        # profile_data_holder.append( ( pupp_file, loc, reso_cnt, clas_cnt, attr_cnt, vari_cnt, time_dura ) )
        if pupp_file not in final_res_dic: 
            final_res_dic[ pupp_file ] = res_tup 
        profile_data_holder.append( ( pupp_file, giveTimeStamp() , time_dura ) )
    profile_df  = pd.DataFrame( profile_data_holder )
    profile_df.to_csv( dir_ +  constants.TIME_DUMP_FILE_NAME , header= constants.TIME_HEADER , index=False, encoding= constants.CSV_ENCODING )
    # profile_df.to_csv( dir_ +  constants.PROFILE_DUMP_FILE_NAME, header= constants.METRIC_HEADER , index=False, encoding= constants.CSV_ENCODING )
    return final_res_dic 


if __name__=='__main__':
    # doFullTaintForSingleScript( '/Users/arahman/TAINTPUP_REPOS/GITLAB/simp@puppetlabs-mysql/manifests/backup/mysqldump.pp' )
    # res_tup = doFullTaintForSingleScript( '/Users/arahman/TAINTPUP_REPOS/OPENSTACK/fuel-plugin-lma-collector-2018-06/deployment_scripts/puppet/modules/lma_collector/manifests/gse_nagios.pp' )
    # res_tup = doFullTaintForSingleScript( '/Users/arahman/TAINTPUP_REPOS/OPENSTACK/fuel-plugin-lma-collector-2018-06/deployment_scripts/puppet/modules/lma_collector/manifests/afd_nagios.pp' )
    
    print('='*50)    




