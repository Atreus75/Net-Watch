import psutil
from classes import NetEvent
from time import sleep

class NetWatch:
    def __init__(self, cooldown=1.0):
        '''
        cooldown: Time between the network data analysis
        '''
        self.cooldown = cooldown
        self.beacon_suspects = []
        pass
    
    def watch(self):
        while True:
            net_activity_org = psutil.net_connections(kind='inet')
            net_activity_uniq = self.clean_net_activity(net_activity_org)
            print(f'[+] Events before cutting: {len(net_activity_org)}. Events after cutting: {len(net_activity_uniq)}')
            for a in net_activity_uniq:
                proc = self.pid_to_process(a.pid)
                print(f'    - PID: {a.pid} | Executable: {proc.info["name"]} | Connection Status: {a.status}')
            sleep(self.cooldown)

    def check_beacon(self):
        pass

    def pid_to_process(self, pid=0):
        '''
        Returns a complete psutil.Process object.\n
        pid: Integer PID number
        '''
        curr_procs = psutil.process_iter(['pid', 'name', 'username'])
        ret = psutil.Process()
        for proc in curr_procs:
            if pid == proc.pid:
                return proc
        return ret
    
    def clean_net_activity(self, activity=[]):
        '''
        Removes irrelevant and duplicated events from the activity list.
        '''
        activity = sorted(activity, key=lambda x: x.pid) # sorting network activities by its processes's pids
        c = -1
        while True:
            c += 1
            if c >= len(activity):
                break
            # Removing duplicated events
            elif c > 0 and activity[c].pid == activity[c-1].pid or activity[c].status not in ['ESTABLISHED', 'LISTENING']:
                activity.remove(activity[c])
                c -= 1
        return activity

if __name__ == '__main__':
    watcher = NetWatch(2)
    try:
        watcher.watch()
    except KeyboardInterrupt:
        print('[-] Terminating.')
