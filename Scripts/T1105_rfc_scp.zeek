##! T1105_rfc_scp.zeek

@load base/frameworks/notice
@load base/protocols/ssh
@load base/protocols/conn

##! Set of variables to tackle this problem
##! Define list of local management boxes approved for SCP/SSH
global auth_managers: set[addr] = { 172.16.11.1 };

##! Define constraints for what entails a high-rate, suspect flow
const max_ssh_duration: interval = 2 min &redef;
const max_ssh_size: count = 2300 &redef;
const max_ssh_rate: count = 1000 &redef;

##! Will ID SSH connections and determine if they are too big or otherwise likely SCP candidates.
event connection_state_remove(c: connection) {
    
    ##! Filter out non-SSH noise looking for presence of appropriate ssh information
    if ( c?$ssh == F ) {
        return;
    }    
    ##! Filter out management noise looking for approved SSH users
    if ( c$id$orig_h in auth_managers ) {
        return;
    }
    ##! For every connection id associated with a SSH session and not approved, 
    ##! evaluate size and duration to determine if likely SCP.
    
    ##! Calculate the byterate, aim is to be flag sessions higher than CLI normal, indicating SCP or tunneling
    local byterate: double;
    
    ##! protect from Divide-by-Zero
    if ( |c$duration| ==0 ){
         byterate = 0;
    }
    if ( |c$duration| != 0 ){
        byterate = c$conn$orig_ip_bytes/ |c$duration|;
    }
    ##! If an SSH session has a ton of bytes, takes too long, or looks too big, it probably is - send an alert and log it!
    if ( (c?$ssh == T) && ((c$duration > max_ssh_duration) || (byterate > max_ssh_rate) || (c$conn$orig_ip_bytes > max_ssh_size))) {
        
        ##! Print out alert to terminal
        print fmt ("[WARNING] Potential unauth SCP detected (ATT&CK T1105)");
        print fmt ("Time: %s TX: %s RX: %s Bytes: %s Duration: %s Connection: %s", strftime("%Y/%M/%d %H:%m:%S", c$conn$ts), c$id$orig_h, c$id$resp_h, c$conn$orig_ip_bytes, c$duration, c$uid ); 
            
        ##! And capture for posterity in notice.log
		NOTICE([
                $note = Weird::Activity, 
				$msg = "Potential unauth SCP detected (ATT&CK T1105)",
				$conn = c
        ]);
        }
    }

