#!/usr/bin/env python3

import re
import os
import sys
import subprocess
import numpy as np

username='huruitao%40kaihong.com'
password='skh123456'
reponame='@gitcode.com/hu-ruitao/communication_wifi'

def printhelp(): 
    print("Need commit dirpath:\n")
    print("For example\n")
    print("python3 .\autocommit.py ./xts_acts_1\n")
    

def getUntrackFileLine(path) -> tuple[str, str, int]:
    try:
        command = f"wc -l \"{path}\""
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout, result.stderr, result.returncode
    except Exception as e:
        return '', str(e), -1 

def getGitShowMod(repoPath, modPath) -> tuple[str, str, int]:
    try:
        result = subprocess.run(
            ['git', '-C', repoPath, 'diff', '--numstat', modPath],
            capture_output=True,
            text=True,
            check=False
        )
        return result.stdout, result.stderr, result.returncode
    except Exception as e:
        return '', str(e), -1

def getGitShowDel(repoPath, delPath) -> tuple[str, str, int]:
    try:
        command = f"git -C {repoPath} show --stat :{delPath} | wc -l"
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout, result.stderr, result.returncode
    except Exception as e:
        return '', str(e), -1

def getGitStatus(repoPath) -> tuple[str, str, int]:
    try:
        result = subprocess.run(
            ['git', '-C', repoPath, 'status'],
            capture_output=True,
            text=True,
            check=False
        )
        return result.stdout, result.stderr, result.returncode
    except Exception as e:
        return '', str(e), -1

def parse_git_status(output):
    result = {
        'modified': [],
        'deleted': [],
        'untracked': []
    }
    
    # 解析修改和删除的文件
    print(f"parse: {output}")
    changes_section = re.search(r'Changes not staged for commit:.*?[\n\r]+.*?[\n\r]+(.*?)(?=\n\n\w|\Z)', output, re.DOTALL)
    if changes_section:
        print(f"changes_section: {changes_section}")
        for line in changes_section.group(1).split('\n'):
            print(f"line: {line}")
            if 'modified:' in line:
                # print(f"modified: {line}")
                result['modified'].append(line.split('modified:')[1].strip())
            elif 'deleted:' in line:
                # print(f"deleted: {line}")
                result['deleted'].append(line.split('deleted:')[1].strip())
    
    # 解析未跟踪的文件
    untracked_section = re.search(r'Untracked files:.*?[\n\r]+.*?[\n\r]+(.*?)(?=\n\n\w|\Z)', output, re.DOTALL)
    if untracked_section:
        for line in untracked_section.group(1).split('\n'):
            if line.strip() and not line.strip().startswith('('):
                result['untracked'].append(line.strip())
    
    return result

def doGitAdd(repoPath, filePath) -> tuple[str, str, int]:
    try:
        command = f"git -C {repoPath} add \"{filePath}\""
        print(f"git add : {command}")
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.stderr:
            print(f"Error: {result.stderr}")
        return result.stdout, result.stderr, result.returncode
    except Exception as e:
        return '', str(e), -1
    
def doGitCommit(repoPath, msg) -> tuple[str, str, int]:
    try:
        command = f"git -C {repoPath} commit -sm \"{msg}\""
        print(f"git commit : {command}")
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.stderr:
            print(f"Error: {result.stderr}")
        return result.stdout, result.stderr, result.returncode
    except Exception as e:
        return '', str(e), -1
    
def doGitPush(repoPath) -> tuple[str, str, int]:
    try:
        command = f"git -C {repoPath} push https://{username}:{password}@{reponame}"
        print(f"gitpush: {command}")
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.stderr:
            print(f"Error: {result.stderr}")
        else:
            print(f"gitpush: {result.stdout}")
        return result.stdout, result.stderr, result.returncode
    except Exception as e:
        return '', str(e), -1

def gitCommit(dirPath, fileMap):
    commitCnt = 0
    for key in fileMap:
        filePath = key
        lineCnt = fileMap[key]
        print(f"gitcommit : {filePath}, {lineCnt}, {commitCnt}")
        if (lineCnt + commitCnt >= 2000):
            print(f"gitCommit commit: {commitCnt}, restCnt: {lineCnt}")
            doGitCommit(dirPath, "commit files bef " + filePath)
            commitCnt = lineCnt
            print(f"gitCommit add: {commitCnt}， {key}, {filePath}")
            doGitAdd(dirPath, filePath.replace(dirPath+os.path.sep, ""))
        else:
            commitCnt += lineCnt
            print(f"gitCommit add: {commitCnt}， {key}, {filePath}")
            doGitAdd(dirPath, filePath.replace(dirPath+os.path.sep, ""))

    if (commitCnt > 0):
        doGitCommit(dirPath, "commit files bef " + filePath)
        commitCnt = 0;
    
    doGitPush(dirPath)


def scanFolder(path):
    fileList = []
    for root, dirs, files in os.walk(path):
        for file in files:
            filePath = os.path.join(root, file)
            fileList.append(filePath)

        for dir in dirs:
            realdir = os.path.join(root, dir)
            # print(f"dir : {realdir}")
            fileretList = scanFolder(realdir)
            
            fileList += fileretList

        return fileList 

def autoCommit(dirPath):
    stdout, stderr, retcode = getGitStatus(dirPath)
    print(f"ac return code: {retcode}")
    print(stdout)
    if stderr:
        print("\n--------Error Output-------")
        print(stderr)
        exit

    parsed = parse_git_status(stdout)
    print("Modified files:", parsed['modified'])
    print("Deleted files:", parsed['deleted'])
    print("Untracked files:", parsed['untracked'])

    fileMap = {}

    for modItem in parsed['modified']:
        realPath = os.path.join(dirPath, modItem)
        is_dir = os.path.isdir(realPath)
        if is_dir:
            fileretList = scanFolder(realPath)
            for fileItem in fileretList:
                stdout, stderr, retcode = getGitShowMod(dirPath, fileItem)
                modsplit = stdout.split('\t')
                # print(f"mod {fileItem} {modsplit[0]} {modsplit[1]}")
                fileMap[fileItem] = int(modsplit[0]) + int(modsplit[1])
                if stderr:
                    print("\n--------Error Output-------")
                    print(stderr)
                    exit
        else:
            stdout, stderr, retcode = getGitShowMod(dirPath, modItem)
            # print(f"mod return code: {retcode}")
            modsplit = stdout.split('\t')
            # print(f"mod {modItem} {modsplit[0]} {modsplit[1]}")
            fileMap[modItem] = int(modsplit[0]) + int(modsplit[1])
            if stderr:
                print("\n--------Error Output-------")
                print(stderr)
                exit

    for delItem in parsed['deleted']:
        realPath = os.path.join(dirPath, delItem)
        is_dir = os.path.isdir(realPath)
        if is_dir:
            fileretList = scanFolder(delItem)
            for fileItem in fileretList:
                stdout, stderr, retcode = getGitShowDel(dirPath, fileItem)
                # print(f"del return code: {retcode}")
                # print(f"del {fileItem} {stdout}")
                fileMap[fileItem] = int(stdout.replace('\n', ''))
                if stderr:
                    print("\n--------del Error Output-------")
                    print(stderr)
                    exit
        else:
            stdout, stderr, retcode = getGitShowDel(dirPath, delItem)
            # print(f"del return code: {retcode}")
            # print(f"del {delItem} {stdout}")
            fileMap[delItem] = int(stdout.replace('\n', ''))
            if stderr:
                print("\n--------del Error Output-------")
                print(stderr)
                exit

    for addItem in parsed['untracked']:
        realPath = os.path.join(dirPath, addItem)
        is_dir = os.path.isdir(realPath)
        if is_dir:
            fileretList = scanFolder(realPath)
            for fileItem in fileretList:
                stdout, stderr, retcode = getUntrackFileLine(fileItem)
                lineres = stdout.split(" ")
                # print(f"add: {retcode}, {fileItem}, stdout: {stdout}")
                if len(lineres) < 2:
                    print(f"警告: 无法解析文件行数，跳过文件: {fileItem}")
                    print(f"命令输出: {stdout}")
                    continue
                filepath = lineres[1].replace('\n', '')
                # print(f"add {filepath} {lineres[0]}")
                fileMap[filepath] = int(lineres[0])
                if stderr:
                    print("\n--------add Error Output-------")
                    print(stderr)
                    exit
        else:
            stdout, stderr, retcode = getUntrackFileLine(realPath)
            # print(f"add return code: {retcode}")
            # print(f"add stdout: {stdout}")
            lineres = stdout.split(" ")
            if len(lineres) < 2:
                print(f"警告: 无法解析文件行数，跳过文件: {realPath}")
                print(f"命令输出: {stdout}")
                continue
            filepath = lineres[1].replace('\n', '')
            # print(f"add {filepath} {lineres[0]}")
            fileMap[filepath] = int(lineres[0])
            if stderr:
                print("\n--------add Error Output-------")
                print(stderr)
                exit

    # print("\n---file map---\n")
    # for key in fileMap:
    #     print(f"fmap: {key}, {fileMap[key]}")
    # print(f"total: {len(fileMap)}")

    gitCommit(dirPath, fileMap)

if __name__ == '__main__':
    print(len(sys.argv))
    testsuite = []
    mustpass = []
    arglen = len(sys.argv)
    
    if arglen < 2:
        printhelp()
        exit
        
    autoCommit(sys.argv[1])
    