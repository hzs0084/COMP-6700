'''
Akond Rahman 
Nov 25, 2020 
Explore Puppet Parser Output 
'''
import os 
import subprocess 


def readAsStr(file_):
    file = open(file_, 'r') 
    full_str = file.read()
    file.close()
    return full_str


def getContentWithStack( parsed_out_file_str ):
    paren_stack = [] 
    tracker_list = []
    for char_index in range(len(parsed_out_file_str)):
        curr_char = parsed_out_file_str[char_index]
        if '(' in curr_char:
                paren_stack.append( char_index )
        if ')' in curr_char:
            if (len(paren_stack) > 0  ):
                returned_elem  = paren_stack.pop(  )
                tracker_list.append(  (returned_elem, char_index) )
    # for tup in tracker_list:
    #     print(parsed_out_file_str[tup[0]+1:tup[-1]]) 
    #     print('*'*25)
    return tracker_list, parsed_out_file_str 



def getAttributes(all_locs, all_as_str): 
    attribDict = {}
    for loc_tup in all_locs:
        loc_str = all_as_str[loc_tup[0]+1:loc_tup[-1]]  
        if '\n' not in loc_str and (loc_str.count('=>') == 1 ) : # last check to handle weirdos like ? $::l23_os (/(?i:redhat7|centos7)/ => false) (:default => true)
            if '=>' in loc_str:
                # print(loc_tup[0], loc_tup[-1], loc_str) 
                key_, value_ = loc_str.split('=>')
                key_, value_ = key_.strip(), value_.strip()
                attribDict[key_] = (loc_tup[0], loc_tup[-1], value_) 
                # print('='*25) 
    return attribDict

def getVars(all_locs, all_as_str): 
    varDict = {}
    for loc_tup in all_locs:
        loc_str = all_as_str[loc_tup[0]+1:loc_tup[-1]]  
        if '\n' not in loc_str: 
            if '=' in loc_str and '=>' not in loc_str : 
                rest_str = loc_str.replace('=', '')
                rest_str = rest_str[1:]
                key_, val_ = rest_str.split(' ')[0], ' '.join(rest_str.split(' ')[1:] )
                varDict[key_] = ( loc_tup[0], loc_tup[1], val_  )
    return varDict 

def getResoName( reso_locs, reso_str, the_name = 'DEFAULT_NAME' ):
    name_cnt_tracker = 0 
    for loc_tup in reso_locs:
        name_cnt_tracker += 1 
        loc_str = reso_str[loc_tup[0]+1:loc_tup[-1]]  
        if( name_cnt_tracker == len(reso_locs) ):
            splitted_strs  = loc_str.split('\n')
            the_name = splitted_strs[0]
    return the_name

def getResoType(reso_str):
    reso_kw =  reso_str.split('\n')[0]
    reso_type = reso_kw.split(' ')[-1] 
    return reso_type 

def getResources(all_locs, all_as_str):
    resoDict = {}
    reso_index = 0 
    for loc_tup in all_locs:
        loc_str = all_as_str[loc_tup[0]+1:loc_tup[-1]] 
        if 'resource' in loc_str and '->' not in loc_str:     
            reso_index += 1 
            reso_locs,  reso_content = getContentWithStack( loc_str  )  
            attrib_per_reso_dict = getAttributes( reso_locs, reso_content )
            # print(reso_content) 
            reso_name  = getResoName( reso_locs, reso_content )
            reso_type  = getResoType( reso_content )
            # print(loc_tup[0], loc_tup[-1] , reso_name, reso_type)
            # print( attrib_per_reso_dict )     
            resoDict[ reso_index ] = ( reso_name, reso_type,  loc_tup[0], loc_tup[-1], attrib_per_reso_dict  )
            # print('#'*10)
    return resoDict     


def sampleMiner(sample_parser_output_file):
    # sample_parser_output_file = 'sample.puppet.parser.txt' 
    full_file_as_str = readAsStr( sample_parser_output_file )
    locations, full_content_as_str = getContentWithStack( full_file_as_str )
    dict_of_attribs = getAttributes( locations, full_content_as_str  )
    dict_of_variables = getVars( locations, full_content_as_str )
    # print(dict_of_variables) 
    dict_of_resources = getResources( locations, full_content_as_str )
    print( dict_of_resources )     

def getPuppetFiles(path_to_dir):
    valid_  = [] 
    for root_, dirs, files_ in os.walk( path_to_dir ):
       for file_ in files_:
           full_p_file = os.path.join(root_, file_)
           if(os.path.exists(full_p_file)):
             if (full_p_file.endswith('.pp')):
               valid_.append(full_p_file)
    return valid_ 

def executeParser(pp_file):
    print('Analyzing:', pp_file)
    TEMP_LOG_FILE = 'temp.output.from.parser.txt'
    command2exec = 'puppet parser  dump --render-as console' +  ' ' + pp_file + ' ' + '>' + ' ' + TEMP_LOG_FILE 
    subprocess.check_output(['bash', '-c', command2exec])
    # try:
    #     command2exec = 'puppet parser  dump --render-as console' +  ' ' + pp_file + ' ' + '>' + ' ' + TEMP_LOG_FILE 
    #     # print(command2exec )
    #     # subprocess.check_output([constants.BASH_CMD, constants.BASH_FLAG, command2exec])
    # except subprocess.CalledProcessError as e_:
    #     print( str(e_) )
    num_lines = sum(1 for line in open( TEMP_LOG_FILE , 'r'))
    print(num_lines) 
    sampleMiner( TEMP_LOG_FILE  )
    os.remove( TEMP_LOG_FILE )
    print('|'*100)



def generator(dir_):
    all_pupp_files = getPuppetFiles(  dir_ )
    for pupp_file in all_pupp_files:
        executeParser( pupp_file )  


if __name__=='__main__':
    # sampleMiner('sample.puppet.parser.txt')

    # dataset_dir = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/'
    # dataset_dir = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/mozi-pupp/'
    # dataset_dir = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/'    
    # generator(dataset_dir) 


