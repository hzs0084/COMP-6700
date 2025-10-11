'''
Akond Rahman
Mar 04, 2021 
Clean up files you don't need
'''
from datetime import datetime
import os
import pandas as pd 
import csv 
import subprocess
import numpy as np
import shutil
from xml.dom import minidom
from xml.parsers.expat import ExpatError
from git import Repo
from git import exc 


def doCleanUp(dir_name):
    pp_, non_pp = [], []
    for root_, dirs, files_ in os.walk(dir_name):
       for file_ in files_:
           full_p_file = os.path.join(root_, file_)
           if(os.path.exists(full_p_file)):
             if (full_p_file.endswith('.pp')):
               pp_.append(full_p_file)
             else:
               non_pp.append(full_p_file)
    for f_ in non_pp:
        os.remove(f_)
    print("="*50)
    print(dir_name )
    print('removed {} non-puppet files, kept {} Puppet files #savespace '.format(len(non_pp), len(pp_)) )
    print("="*50 )

def getCount(dir_name):
    pp_, non_pp = [], []
    for root_, dirs, files_ in os.walk(dir_name):
       for file_ in files_:
           full_p_file = os.path.join(root_, file_)
           if(os.path.exists(full_p_file)) :
             if (full_p_file.endswith('pp')):
               pp_.append(full_p_file)
             else:
               non_pp.append(full_p_file)    

    print( 'DIR:{},Puppet:{}, Non-Puppet:{}, Total:{}'.format(dir_name, len(pp_), len(non_pp), len(pp_) + len(non_pp)) )
    return len( pp_ )


def getDevEmailForCommit(repo_path_param, hash_):
    author_emails = []

    cdCommand     = "cd " + repo_path_param + " ; "
    commitCountCmd= " git log --format='%ae'" + hash_ + "^!"
    command2Run   = cdCommand + commitCountCmd

    author_emails = str(subprocess.check_output(['bash','-c', command2Run]))
    author_emails = author_emails.split('\n')
    author_emails = [x_.replace(hash_, '') for x_ in author_emails if x_ != '\n' and '@' in x_ ] 
    author_emails = [x_.replace('^', '') for x_ in author_emails if x_ != '\n' and '@' in x_ ] 
    author_emails = [x_.replace('!', '') for x_ in author_emails if x_ != '\n' and '@' in x_ ] 
    author_emails = [x_.replace('\\n', ',') for x_ in author_emails if x_ != '\n' and '@' in x_ ] 
    try:
        author_emails = author_emails[0].split(',')
        author_emails = [x_ for x_ in author_emails if len(x_) > 3 ] 
        author_emails = list(np.unique(author_emails) )
    except IndexError as e_:
        pass
    return author_emails  

def days_between(d1_, d2_): ## pass in date time objects, if string see commented code 
    # d1_ = datetime.strptime(d1_, "%Y-%m-%d")
    # d2_ = datetime.strptime(d2_, "%Y-%m-%d")
    return abs((d2_ - d1_).days)


def getDevDayCount(full_path_to_repo, branchName='master', explore=1000):
    repo_emails = []
    all_commits = []
    repo_emails = []
    all_time_list = []
    ds_life_days, ds_life_months  = 0, 0 
    if os.path.exists(full_path_to_repo):
        repo_  = Repo(full_path_to_repo)
        try:
           all_commits = list(repo_.iter_commits(branchName))   
        except exc.GitCommandError:
           print('Skipping this repo ... due to branch name problem', full_path_to_repo )
        for commit_ in all_commits:
                commit_hash = commit_.hexsha

                emails = getDevEmailForCommit(full_path_to_repo, commit_hash)
                repo_emails = repo_emails + emails

                timestamp_commit = commit_.committed_datetime
                str_time_commit  = timestamp_commit.strftime('%Y-%m-%d') ## date with time 
                all_time_list.append( str_time_commit )

    else:
        repo_emails = [ str(x_) for x_ in range(10) ]
    all_day_list   = [datetime(int(x_.split('-')[0]), int(x_.split('-')[1]), int(x_.split('-')[2]), 12, 30) for x_ in all_time_list]
    if len(all_day_list) > 0:
        min_day        = min(all_day_list) 
        max_day        = max(all_day_list) 
        ds_life_days   = days_between(min_day, max_day)
        ds_life_months = round(float(ds_life_days)/float(30), 5)
    
    return len(repo_emails) , len(all_commits) , ds_life_days, ds_life_months 

def checkFilterStatus(root_dir_path):
    list_subfolders_with_paths = [f.path for f in os.scandir(root_dir_path) if f.is_dir()]
    all_list = []
    count    = 0 
    for dirName in list_subfolders_with_paths:
        count += 1
        print(dirName)  
        eurekaInMain, bootInMain, dev_count, all_file_count, java_count, config_count, sql_count  = 0 , 0 , 0, 0, 0, 0, 0
        all_file_count                                 = sum([len(files) for r_, d_, files in os.walk(dirName)]) 
        pp_count                                       = getCount(dirName) 
        dev_count, commit_count, age_days, age_months  = getDevDayCount(dirName)
        tup = ( count,  dirName,  dev_count, all_file_count, pp_count ,  commit_count, age_months)
        print('*'*10)
        all_list.append( tup ) 
    df_ = pd.DataFrame( all_list ) 
    df_.to_csv('/Users/arahman/TAINTPUP_REPOS/OPENSTACK_BREAKDOWN.csv', header=['INDEX', 'REPO', 'DEVS', 'FILES', 'PP_FILES', 'COMMITS', 'AGE_MONTHS'] , index=False, encoding='utf-8')    


                        


if __name__=='__main__':
#    the_dir = '/Users/arahman/TAINTPUP_REPOS/GITHUB/'
#    the_dir = '/Users/arahman/TAINTPUP_REPOS/GITLAB/'
#    the_dir = '/Users/arahman/TAINTPUP_REPOS/MOZILLA/'
#    the_dir = '/Users/arahman/TAINTPUP_REPOS/OPENSTACK/'
#    the_dir = '/Users/arahman/TAINTPUP_REPOS/WIKIMEDIA/'

   doCleanUp(the_dir)

#    checkFilterStatus( the_dir )
