import os
import pandas as pd 
import csv 
import subprocess
import numpy as np
import shutil
from git import Repo
from git import exc 
from xml.dom import minidom
from xml.parsers.expat import ExpatError
import time 
import  datetime 


def giveTimeStamp():
  tsObj = time.time()
  strToret = datetime.datetime.fromtimestamp(tsObj).strftime('%Y-%m-%d %H:%M:%S')
  return strToret

def getDevEmailForCommit(repo_path_param, hash_):
    author_emails = []

    cdCommand         = "cd " + repo_path_param + " ; "
    commitCountCmd    = " git log --format='%ae'" + hash_ + "^!"
    command2Run = cdCommand + commitCountCmd

    author_emails = str(subprocess.check_output(['bash','-c', command2Run]))
    author_emails = author_emails.split('\n')
    # print(type(author_emails)) 
    author_emails = [x_.replace(hash_, '') for x_ in author_emails if x_ != '\n' and '@' in x_ ] 
    author_emails = [x_.replace('^', '') for x_ in author_emails if x_ != '\n' and '@' in x_ ] 
    author_emails = [x_.replace('!', '') for x_ in author_emails if x_ != '\n' and '@' in x_ ] 
    author_emails = [x_.replace('\\n', ',') for x_ in author_emails if x_ != '\n' and '@' in x_ ] 
    try:
        author_emails = author_emails[0].split(',')
        author_emails = [x_ for x_ in author_emails if len(x_) > 3 ] 
        # print(author_emails) 
        author_emails = list(np.unique(author_emails) )
    except IndexError as e_:
        pass
    return author_emails  

def getDevCount(full_path_to_repo, branchName='master', explore=1000):
    repo_emails = []
    all_commits = []
    repo_emails = []
    if os.path.exists(full_path_to_repo):
        repo_  = Repo(full_path_to_repo)
        try:
           all_commits = list(repo_.iter_commits(branchName))   
        except exc.GitCommandError:
           print('Skipping this repo ... due to branch name problem', full_path_to_repo )
        # only check commit by commit if less than explore threshold
        if len( all_commits ) < explore:
            for commit_ in all_commits:
                commit_hash = commit_.hexsha
                emails = getDevEmailForCommit(full_path_to_repo, commit_hash)
                repo_emails = repo_emails + emails
        else:
            repo_emails = [ str(x_) for x_ in range(10) ]
    return len(repo_emails) 


def makeChunks(the_list, size_):
    for i in range(0, len(the_list), size_):
        yield the_list[i:i+size_]

def cloneRepo(repo_name, target_dir):
    cmd_ = "git clone " + repo_name + " " + target_dir 
    try:
       subprocess.check_output(['bash','-c', cmd_])    
    except subprocess.CalledProcessError:
       print('Skipping this repo ... trouble cloning repo:', repo_name )

def dumpContentIntoFile(strP, fileP):
    fileToWrite = open( fileP, 'w')
    fileToWrite.write(strP )
    fileToWrite.close()
    return str(os.stat(fileP).st_size)




def deleteRepo(dirName, type_):
    print(':::' + type_ + ':::Deleting ', dirName)
    try:
        if os.path.exists(dirName):
            shutil.rmtree(dirName)
    except OSError:
        print('Failed deleting, will try manually')             

def getPuppetUsage(path2dir): 
    usageCount = 0
    for root_, dirnames, filenames in os.walk(path2dir):
        for file_ in filenames:
            full_path_file = os.path.join(root_, file_) 
            if(os.path.exists(full_path_file)):
                if (file_.endswith('pp'))  :
                    usageCount = usageCount + 1

    return usageCount                         

def cloneRepos(repo_list, bootThreshold = 5.0): 
    counter = 0     
    str_ = ''
    for repo_ in repo_list:
            counter += 1 
            print('Cloning ', repo_ )
            dirName = '/Users/arahman/TAINTPUP_REPOS/GITHUB/' + repo_.split('/')[-3] + '@' + repo_.split('/')[-2] 
            cloneRepo(repo_, dirName )
            all_fil_cnt = sum([len(files) for r_, d_, files in os.walk(dirName)])
            if (all_fil_cnt <= 0):
               deleteRepo(dirName, 'NO_FILES')
            else: 
                puppUsage = getPuppetUsage(dirName) 
                puppProp  = (float(puppUsage) / float(all_fil_cnt) ) * 100
                if (puppProp <= bootThreshold ):
                    deleteRepo(dirName,  str(puppProp) +  '_NOT_ENOUGH_PUPPET')
            print('#'*100 )
            str_ = str_ + str(counter) + ',' +  repo_ + ',' + dirName + ','  + str(puppProp) + ','   + '\n'
            print("So far we have processed {} repos".format(counter) )
            if((counter % 50) == 0):
                dumpContentIntoFile(str_, 'github_taintpup_tracker_completed_repos.csv')
            print('#'*100)




if __name__=='__main__':
    '''
    '''

    t1 = time.time()
    print('Started at:', giveTimeStamp() )
    print('*'*100 )

    repos_df = pd.read_csv('/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/MiningWork/github_repos_puppet_filtered.csv')
    list_    = repos_df['repo_url'].tolist()
    list_    = np.unique(list_)

    print('Repos to download:', len(list_)) 

    cloneRepos(list_)

    print('*'*100 )
    print('Ended at:', giveTimeStamp() )
    print('*'*100 )
    t2 = time.time()
    time_diff = round( (t2 - t1 ) / 60, 5) 
    print('Duration: {} minutes'.format(time_diff) )
    print( '*'*100  )    