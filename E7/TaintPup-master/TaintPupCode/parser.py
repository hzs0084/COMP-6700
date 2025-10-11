'''
Akond Rahman 
Dec 09, 2020 
Levarage Built-in Puppet Parser 
'''

import os 
import subprocess 
import constants 

def getContentAsList(path2File):
    data = None 
    with open(path2File, constants.FILE_READ_MODE) as file_:
        try:
            data = file_.read()
        except UnicodeDecodeError as err_:
            data = constants.NULL_SYMBOL
            print( str( err_ ) )

    data_ls = data.split(constants.NEWLINE_CONSTANT) 
    return data_ls 

def readAsStr(file_):
    file = open(file_, constants.FILE_READ_MODE) 
    full_str = file.read()
    file.close()
    return full_str


def getSuspComments( file_ ):  
    comment_files =  []
    data_as_ls = getContentAsList( file_ )  
    comment_as_ls = [z.split( constants.COMMENT_SYMBOL )[1:] for z in data_as_ls if (constants.COMMENT_SYMBOL in z)  ] 
    for comment_item in comment_as_ls:
        comment = constants.WHITESPACE_SYMBOL.join( comment_item  )
        comment = comment.lower() 
        if(any(x_ in comment for x_ in constants.CWE_SUSP_COMMENT_LIST )) and ( constants.DEBUG_KW not in comment ) :
            comment_files.append(  comment )
    
    return comment_files  

def getContentWithStack( parsed_out_file_str ):
    paren_stack = [] 
    tracker_list = []
    for char_index in range(len(parsed_out_file_str)):
        curr_char = parsed_out_file_str[char_index]
        if constants.LPAREN_SYMBOL in curr_char:
                paren_stack.append( char_index )
        if constants.RPAREN_SYMBOL in curr_char:
            if (len(paren_stack) > 0  ):
                returned_elem  = paren_stack.pop(  )
                tracker_list.append(  (returned_elem, char_index) )
    return tracker_list , parsed_out_file_str


def check4InavlidAttrKeyword( key_str ):
    flag_ = False
    if ( any(x_ in key_str for x_ in constants.INVALID_ATTRIBUTE_KEYWORDS ) ):
        flag_ = True 
    return flag_

def getAttributes(all_locs, all_as_str): 
    attribDict = {}
    attribCnt  = 0 
    for loc_tup in all_locs:
        loc_str = all_as_str[loc_tup[0]+1:loc_tup[-1]]  
        # print(loc_str)
        # print('*'*25)
        if  (loc_str.count( constants.ATTRIBUTE_SYMBOL ) == 1 ) : 
            '''
            newlines are messy for attributes 
            only allow newlines that have string cotenation operation 
            '''
            # print(loc_tup[0], loc_tup[-1], loc_str)             
            if ( constants.NEWLINE_CONSTANT  in loc_str and constants.CONCAT_KEYWORD in loc_str) or (constants.NEWLINE_CONSTANT not in loc_str) :
                if constants.ATTRIBUTE_SYMBOL in loc_str :
                    attribCnt += 1 
                    key_, value_ = loc_str.split( constants.ATTRIBUTE_SYMBOL  )
                    key_, value_ = key_.strip(), value_.strip()

                    '''
                    check for invalid parsing key words like block, resource 
                    '''
                    if( check4InavlidAttrKeyword(  key_ ) == False ):
                        # same attribute can appear in many places , so using count 
                        attribDict[attribCnt] = (loc_tup[0], loc_tup[-1], key_,  value_) 
            # print('='*25) 
    return attribDict

def getVars(all_locs, all_as_str): 
    varDict = {}
    # print(all_as_str)
    for loc_tup in all_locs:
        loc_str = all_as_str[loc_tup[0]+1:loc_tup[-1]]  
        # print(loc_str)
        # print('*'*25)
        if constants.NEWLINE_CONSTANT not in loc_str: 
            '''
            if a variable has no value assigned like `$nuage_vsd_password` then we are not tracking that 
            Makes sense for a single script taint tracking
            Need to track for cross script tracking ... create and return  separate dict called null_var_dict 
            '''
            if constants.EQUAL_SYMBOL in loc_str and constants.ATTRIBUTE_SYMBOL not in loc_str : 
                rest_str = loc_str.replace(constants.EQUAL_SYMBOL, constants.NULL_SYMBOL) 
                rest_str = rest_str[1:]
                key_, val_ = rest_str.split(constants.WHITESPACE_SYMBOL)[0], constants.WHITESPACE_SYMBOL.join(rest_str.split(constants.WHITESPACE_SYMBOL)[1:] )
                if (key_ != constants.ARAMETERS_KEYWORD ) and (key_!= constants.PARAMETERS_KEYWORD):
                    varDict[key_] = ( loc_tup[0], loc_tup[1], val_  )
    return varDict 

def getResoName( reso_locs, reso_str, the_name = constants.DEFAULT_RESO_NAME ):
    name_cnt_tracker = 0 
    for loc_tup in reso_locs:
        name_cnt_tracker += 1 
        loc_str = reso_str[loc_tup[0]+1:loc_tup[-1]]  
        if( name_cnt_tracker == len(reso_locs) ):
            splitted_strs  = loc_str.split( constants.NEWLINE_CONSTANT )
            the_name = splitted_strs[0]
    return the_name

def getResoType(reso_str):
    reso_kw =  reso_str.split( constants.NEWLINE_CONSTANT  )[0]
    reso_type = reso_kw.split( constants.WHITESPACE_SYMBOL )[-1] 
    return reso_type 

def getResources(all_locs, all_as_str):
    resoDict = {}
    reso_index = 0 
    for loc_tup in all_locs:
        loc_str = all_as_str[loc_tup[0]+1:loc_tup[-1]] 
        if constants.RESOURCE_KEYWORD in loc_str and constants.ARROWHEAD_SYMBOL not in loc_str:     
                reso_index += 1 
                reso_locs,  reso_content = getContentWithStack( loc_str  )  
                attrib_per_reso_dict = getAttributes( reso_locs, reso_content )
                reso_name  = getResoName( reso_locs, reso_content )
                reso_type  = getResoType( reso_content )
                resoDict[ reso_index ] = ( reso_name, reso_type,  loc_tup[0], loc_tup[-1], attrib_per_reso_dict  )
    return resoDict     


def getClassName( all_locs, all_strs , class_name = constants.DEFAULT_CLASS_NAME, inherit_name = constants.DEFAULT_INHERIT_NAME ):
    if(len(all_locs) > 0 ):
        name_start_pos, name_end_pos = all_locs[0]
        temp_inherit_name = all_strs[name_start_pos + 1 :name_end_pos]
        temp_class_name = all_strs[0 : name_start_pos ]
        if ( constants.CLASS_KEYWORD in temp_class_name ):
            class_name = temp_class_name
            class_name = class_name.replace( constants.CLASS_KEYWORD, constants.NULL_SYMBOL  )        
        if ( constants.INHERITS_KEYWORD in temp_inherit_name ):
            inherit_name = temp_inherit_name
            inherit_name = inherit_name.replace( constants.INHERITS_KEYWORD, constants.NULL_SYMBOL  )        
        class_name,  inherit_name = class_name.strip() ,  inherit_name.strip()
    return  class_name,  inherit_name


def getClasses(all_locs, all_as_str):
    classDict = {}
    class_index = 0 
    for loc_tup in all_locs:
        loc_str = all_as_str[loc_tup[0]+1:loc_tup[-1]] 
        if constants.CLASS_KEYWORD in loc_str :     
            class_index += 1 
            class_locs,  class_content = getContentWithStack( loc_str  )  
            class_name, inherit_name = getClassName( class_locs, class_content ) 
            var_per_class_dict = getVars( class_locs, class_content )  
            attr_per_class_dic = getAttributes( class_locs, class_content )

            '''
            Needed to handle arameters and parameters and block 
            '''
            if constants.ARAMETERS_KEYWORD in var_per_class_dict: del var_per_class_dict[ constants.ARAMETERS_KEYWORD ]          
            if constants.PARAMETERS_KEYWORD in var_per_class_dict: del var_per_class_dict[ constants.PARAMETERS_KEYWORD ]
            if constants.ARAMETERS_KEYWORD in attr_per_class_dic: del attr_per_class_dic[ constants.ARAMETERS_KEYWORD ]          
            if constants.PARAMETERS_KEYWORD in attr_per_class_dic: del attr_per_class_dic[ constants.PARAMETERS_KEYWORD ]

            if (constants.PARAMETERS_KEYWORD in class_name or constants.BLOCK_KEYWORD in class_name ) and (constants.WHITESPACE_SYMBOL in class_name): 
                class_name = class_name.split(constants.WHITESPACE_SYMBOL)[0]  
            if (constants.INVALID_CLASS_KW not in class_name): 
                classDict[ class_index ] = ( class_name, inherit_name, loc_tup[0], loc_tup[-1], var_per_class_dict , attr_per_class_dic )
    return classDict    

def getWhenBlock(case_locations, case_full_content):
    when_block_dict = {}
    when_block_index = 0 
    for loc_tup in case_locations:
        loc_str = case_full_content[loc_tup[0]+1:loc_tup[-1]] 
        if constants.WHEN_KEYWORD in loc_str[0:loc_tup[0] ] and constants.CASE_KEYWORD not in loc_str[0:loc_tup[0] ] :         
            when_block_index += 1 
            when_locs, when_content = getContentWithStack( loc_str )    
            '''
            as we are interested to see branches within the switch case statement 
            we will just take the first level of when block by using the first tuple in the location list 
            '''
            # print(when_locs) 
            # print(when_content) 
            if len( when_locs ) > 0: 
                first_level_when_block = getContentWithStack( when_content[when_locs[0][0] : when_locs[0][-1] ]   )
                when_block_dict[when_block_index] = first_level_when_block
    return when_block_dict 

def getCaseWhenBlock(locs, contents):
    case_block_dict = {}
    case_block_index = 0 
    for loc_tup in locs:
        loc_str = contents[loc_tup[0]+1:loc_tup[-1]] 
        if (constants.CASE_KEYWORD in loc_str) and ( any(x_ in loc_str for x_ in constants.INVALID_SWITCH_CASE_KEYWORDS  ) == False ):       
            case_block_index += 1 
            case_locs, case_content = getContentWithStack( loc_str )
            if(len(case_locs) > 0):
                if( constants.CASE_KEYWORD in case_content[0:case_locs[0][0]]):
                    whensDict = getWhenBlock(case_locs,  loc_str ) 
                    case_block_dict[case_block_index] = (case_locs, case_content, whensDict)
    return case_block_dict 


def getFunctions( locs, texts  ):
    func_dict = {}
    func_index = 0 
    for loc_tup in locs:
        loc_str = texts[loc_tup[0]+1:loc_tup[-1]] 
        if constants.INVOKE_KEYWORD in loc_str :
            func_locs, func_content = getContentWithStack( loc_str )  
            if(len( func_locs ) == 0 ):
                if( constants.INVOKE_KEYWORD in func_content ) and (constants.INCLUDE_KEYWORD not in func_content) :
                    func_index += 1 
                    func_content = func_content.replace(constants.INVOKE_KEYWORD, constants.NULL_SYMBOL) 
                    func_name    = func_content.split(constants.WHITESPACE_SYMBOL)[1].strip() 
                    func_parms   = func_content.split(constants.WHITESPACE_SYMBOL)[2:] 
                    func_dict[func_index] = (constants.DUMMY_FUNC_ASSIGNEE,   func_name, func_parms) 
        elif (constants.CALL_KW  in loc_str): 
            per_line_locs, per_line_content = getContentWithStack( loc_str )  
            if (constants.CALL_KW  in per_line_content) and (constants.NEWLINE_CONSTANT not in per_line_content) and (constants.EQUAL_SYMBOL in per_line_content):  
                    func_index += 1 
                    splitted_list = per_line_content.split( constants.CALL_KW )
                    func_call_text = splitted_list[-1]

                    func_val_assignee = splitted_list[0] 
                    func_val_assignee = func_val_assignee.replace( constants.ATTRIBUTE_SYMBOL, constants.NULL_SYMBOL )
                    func_val_assignee = func_val_assignee.replace( constants.EQUAL_SYMBOL, constants.NULL_SYMBOL )
                    func_val_assignee = func_val_assignee.replace( constants.DOLLAR_SYMBOL, constants.NULL_SYMBOL )
                    func_val_assignee = func_val_assignee.strip() 

                    func_call_list = func_call_text.split( constants.WHITESPACE_SYMBOL )
                    func_call_list = [z_ for z_ in func_call_list if len(z_) > 0 ] 
                    func_name      = func_call_list[0].strip()
                    func_params    = func_call_list[1:]
                    func_dict[func_index] = (func_val_assignee,   func_name, func_params) 
    return func_dict 


def mineParseOutput(parser_output_str, pp_original_file):
    full_file_as_str = parser_output_str 
    # print(full_file_as_str) 
    '''
    As puppet parser output strips all comments we need the original file name as well 
    to get comments 
    '''

    locations, full_content_as_str = getContentWithStack( full_file_as_str )

    
    dict_of_resources              = getResources( locations, full_content_as_str )
    dict_of_classes                = getClasses( locations, full_content_as_str ) 
    dict_of_all_attribs            = getAttributes( locations, full_content_as_str  )
    dict_of_all_variables          = getVars( locations, full_content_as_str )
    dict_of_switch_cases           = getCaseWhenBlock( locations, full_content_as_str )
    list_of_susp_comments          = getSuspComments( pp_original_file )
    dict_of_funcs                  = getFunctions( locations, full_content_as_str )

    # print(dict_of_all_attribs) 
    return dict_of_resources, dict_of_classes, dict_of_all_attribs, dict_of_all_variables, dict_of_switch_cases, list_of_susp_comments , dict_of_funcs


def executeParser(pp_file):
    parseResults = None 
    if (os.path.exists(pp_file) ):
        try:
            command2exec   = constants.NATIVE_PUPPET_PARSER_CMD +  constants.WHITESPACE_SYMBOL + pp_file 
            subprocess_out = subprocess.check_output([constants.BASH_CMD, constants.BASH_FLAG, command2exec])
            subprocess_str = subprocess_out.decode( constants.CSV_ENCODING ) 
        except subprocess.CalledProcessError as e_:
            subprocess_str = constants.NULL_SYMBOL
            print( str(e_) )
        # num_lines = sum(1 for line in open( constants.TEMP_LOG_FILE , constants.FILE_READ_MODE ))
        
        parseResults = mineParseOutput( subprocess_str, pp_file ) 

    return parseResults 



if __name__=='__main__':
    # test_pp_file = 'test.api.pp'
    # test_pp_file = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-ceph-2018-06/manifests/rgw/keystone/auth.pp'
    # test_pp_file = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/sample-puppet-scripts/manifests/init1.pp' 
    # test_pp_file = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-tripleo-2018-06/manifests/profile/base/pacemaker.pp'
    # test_pp_file = '/Users/arahman/TAINTPUP_REPOS/GITLAB/simp@puppetlabs-postgresql/manifests/repo.pp'
    test_pp_file = '/Users/arahman/TAINTPUP_REPOS/GITHUB/derekhiggins@packstack/packstack/puppet/templates/cinder.pp'

    executeParser( test_pp_file )
