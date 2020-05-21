##! T1021_ssh_brute.zeek

@load base/frameworks/notice
@load protocols/ssh/detect-bruteforcing

##! Redefine the guessing timeout, don't forget the interval units (default minutes)

redef SSH::guessing_timeout=3 mins;

##! Identify the authorized guessors (VAM tools, internal pen testers, etc.)
##! Use CIDR notation, index is Client, value is Server (table [subnet] of subnet)

redef SSH::ignore_guessers[172.16.1.0/24] = 172.16.2.0/24;

##! Redefine the guess limit per unit time - balance between this
##! and guessing timeout drives sensitivity

redef SSH::password_guesses_limit=5;

event NetControl::init()
    {
    local debug_plugin = NetControl::create_debug(T);
    NetControl::activate(debug_plugin, 0);
    }

##! Uses Notice::Policy framework to provide alerting outside of event
##! processing engines(https://docs.zeek.org/en/current/frameworks/notice.html)

hook Notice::policy(n: Notice::Info)
  {
  if ( n$note == SSH::Password_Guessing )
      add n$actions[Notice::ACTION_LOG];
  }

