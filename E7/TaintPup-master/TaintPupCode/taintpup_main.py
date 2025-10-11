'''
Akond Rahman 
Dec 09, 2020 
Main file to pass in repos 
'''
import orchestra 
import pandas as pd 
import constants 
import pickle
import time 
import  datetime 
import EmpiricalAnalysis 

def getCountFromTuple(tu_):
    cnt  = 0 
    # sample format for secret dict: secret_taint_dict, cross_secret_dict, secret_dict_attr, secret_dict_vars 
    taint_dic, cross_taint_dic, attrib_dic , _ = tu_  # we will not use non-tainted security smells so skipping last element of tuple 
    '''
    # we will not consider cross dict as we are calculating within script smells 
    # one hard-coded secret can be assigned in more places , so get the list 
    for name_, data_ in taint_dic.items(): 
        cnt = cnt + len( data_ )
    '''
    # all tainted secret-related variables are tracked as dictionary index 
    cnt = cnt + len(taint_dic) 
    # all attribute secrets are tracked as dictionary index 
    cnt = cnt + len(attrib_dic) 
    # all cross script tainted secret-related variables are tracked as dictionary index 
    cnt = cnt + len(cross_taint_dic) 
    return cnt 

def getCountFromDic(dic_):
    cnt  = 0 
    # one hard-coded secret can be assigned in more places , so get the list 
    for name_, data_ in dic_.items(): 
        cnt = cnt + len( data_ )
    return cnt 


def constructDumpList(file_, lis_tup): 
    temp = [] 
    for tup in lis_tup:
        if (len(tup) == 5): 
            temp.append( ( file_, tup[0], tup[1], tup[2], tup[3], tup[4] )  )
        elif (len(tup) == 7): 
            temp.append( ( file_, tup[0], tup[1], tup[2], tup[3], tup[4], tup[5], tup[6] )  )
        elif (len(tup) == 3): 
            temp.append( ( file_, tup[0], tup[1], tup[2]  )  )
    return temp 

def dumpInsights( insight_dict , org_name): 
    dumpNotUsed, dumpHop, dumpResource = [], [], []
    for script, scripts_insights in insight_dict.items(): 
        notUsed, hop, resource, tot_smell_count = scripts_insights 
        dumpNotUsed  = dumpNotUsed  + constructDumpList( script, notUsed )
        if tot_smell_count > 0:
            dumpHop      = dumpHop      + constructDumpList( script, hop )
            dumpResource = dumpResource + constructDumpList( script, resource )
    
    df_not_used = pd.DataFrame( dumpNotUsed )
    df_not_used.to_csv( constants.DUMP_NOTUSED_FILE + org_name + constants.CSV_FILE_EXT , header= constants.NOTUSED_HEADER , index=False, encoding= constants.CSV_ENCODING )    
    
    df_hop = pd.DataFrame( dumpHop )
    df_hop.to_csv( constants.DUMP_HOPCOUNT_FILE + org_name + constants.CSV_FILE_EXT, header= constants.HOP_HEADER , index=False, encoding= constants.CSV_ENCODING )    
    
    df_resource = pd.DataFrame( dumpResource )
    df_resource.to_csv( constants.DUMP_RESOURCE_FILE + org_name + constants.CSV_FILE_EXT, header= constants.RESO_HEADER , index=False, encoding= constants.CSV_ENCODING )            


def processResults( res_dic, res_csv_name, res_pkl_name, org_nam ):
    res_holder  = [] 
    insights_dict = {} 
    for file_name, scan_results in res_dic.items():
        insights_not_used_holder, insights_hop_holder, insights_reso_holder = [] , [], []
        # last element of scan results is dict of resources : will be used later 
        susp_cnt, switch_cnt, ip_tuple, http_tuple, secret_tuple, empty_pass_tuple, default_admin_tuple, weak_cry_tuple, _ = scan_results
        
        ip_count       = getCountFromTuple( ip_tuple )
        http_count     = getCountFromTuple( http_tuple )
        secret_count   = getCountFromTuple( secret_tuple  )
        empty_pass_cnt = getCountFromTuple( empty_pass_tuple )
        
        default_taint_dict, _ = default_admin_tuple # last one is default admin without taint , will not go directly to count
        weak_cry_dic_taint, _ = weak_cry_tuple # last one is weak crypto without taint , will not go directly to count
        dflt_adm_cnt   = getCountFromDic( default_taint_dict )
        weak_cry_cnt   = getCountFromDic( weak_cry_dic_taint )
        
        total_count    = sum( [susp_cnt, switch_cnt, ip_count, http_count, secret_count, empty_pass_cnt, dflt_adm_cnt, weak_cry_cnt] )
        
        full_res_tup   = ( file_name, susp_cnt, switch_cnt, ip_count, http_count, secret_count, empty_pass_cnt, dflt_adm_cnt, weak_cry_cnt, total_count )
        res_holder.append( full_res_tup ) 
        # print( full_res_tup )
        # print('='*80)
        '''
        extra insights zone , segment#1: not used zone 
        '''
        notUsedTuple  =  EmpiricalAnalysis.mineNotUsedSmells(scan_results )
        for list_ in notUsedTuple:
            insights_not_used_holder = insights_not_used_holder + list_ 
        '''
        extra insights zone , segment#2: hop zone 
        '''
        hopTuple  =  EmpiricalAnalysis.mineSmellHops (scan_results )
        for list_ in hopTuple:
            insights_hop_holder = insights_hop_holder + list_ 
        '''
        extra insights zone , segment#3: resource zone 
        '''
        resoTuple  =  EmpiricalAnalysis.mineSmellyResources (scan_results )
        for list_ in resoTuple:
            insights_reso_holder = insights_reso_holder + list_ 
        '''
        extra insights zone , hold the results 
        '''          
        insights_dict[ file_name ] = ( insights_not_used_holder, insights_hop_holder, insights_reso_holder, total_count )


    df_ = pd.DataFrame( res_holder )
    df_.to_csv( res_csv_name, header= constants.CSV_HEADER , index=False, encoding= constants.CSV_ENCODING )
    pickle.dump( res_dic, open( res_pkl_name , constants.PKL_WRITE_MODE ) )

    '''
    extra insights zone , dump the results 
    '''  

    dumpInsights( insights_dict  , org_nam )


def giveTimeStamp():
  tsObj = time.time()
  strToret = datetime.datetime.fromtimestamp(tsObj).strftime(constants.TIME_FORMAT) 
  return strToret

if __name__=='__main__':
    t1 = time.monotonic()
    print('Started at:', giveTimeStamp() )
    print('*'*100 )

    # dataset_dir = '/Users/arahman/TAINTPUP_REPOS/GITHUB/'
    # results_csv = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output/V9_GITH.csv'
    # results_pkl = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output/V9_GITH.pkl'    
    # org_        = 'GITHUB'


    # dataset_dir = '/Users/arahman/TAINTPUP_REPOS/GITLAB/'
    # results_csv = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output/V9_GITL.csv'
    # results_pkl = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output/V9_GITL.pkl'    
    # org_        = 'GITLAB'

    # dataset_dir = '/Users/arahman/TAINTPUP_REPOS/MOZILLA/'
    # results_csv = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output/V9_MOZI.csv'
    # results_pkl = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output/V9_MOZI.pkl'    
    # org_        = 'MOZI'

    # dataset_dir = '/Users/arahman/TAINTPUP_REPOS/OPENSTACK/'
    # results_csv = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output/V9_OSTK.csv'
    # results_pkl = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output/V9_OSTK.pkl'    
    # org_        = 'OSTK'


    # dataset_dir = '/Users/arahman/TAINTPUP_REPOS/WIKIMEDIA/' 
    # results_csv = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output/V9_WIKI.csv'
    # results_pkl = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output/V9_WIKI.pkl'
    # org_        = 'WIKI'

    # dataset_dir = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/test-pupp/' 
    # results_csv = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output/V9_TEST.csv'
    # results_pkl = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output/V9_TEST.pkl'
    # org_        = 'TEST'

    
    full_res_dic  = orchestra.orchestrateWithTaint( dataset_dir )    
    processResults( full_res_dic, results_csv, results_pkl, org_  )
    
    print('*'*100 )
    print('Ended at:', giveTimeStamp() )
    print('*'*100 )
    t2 = time.monotonic()
    time_diff = round( (t2 - t1 ) / 60, 5) 
    print('Duration: {} minutes'.format(time_diff) )
    print( '*'*100  )        