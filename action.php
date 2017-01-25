<?php
/**
 * DokuWiki Plugin iptrust2 (Action Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Alexander Sulfrian <alexander@sulfrian.net>
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

class action_plugin_iptrust2 extends DokuWiki_Action_Plugin {

    private function inet_to_bits($inet) {
        $len = strlen($inet);

        $unpacked = unpack('A*', $inet);
        $unpacked = str_split($unpacked[1]);
        $unpacked = array_pad($unpacked, $len, "\0");

        $binaryip = '';
        foreach ($unpacked as $char) {
            $binaryip .= sprintf('%08b', ord($char));
        }
        return $binaryip;
    }

    private function check_ip($ip, $nets) {
        $ip_n = inet_pton($ip);
        if ($ip_n === false) return false;

        $ip_b = $this->inet_to_bits($ip_n);
    
        foreach ($nets as $net) {
            $pos = strpos($net, '/');
            if ($pos === false) {
                $net_n = inet_pton($net);
                if ($net_n === false) return false;

                if ($net_n === $ip_n) {
                    return true;
                }
            }
            else {
                $net_n = inet_pton(substr($net, 0, $pos));
                if ($net_n === false) return false;
    
                if (strlen($ip_n) != strlen($net_n)) {
                    continue;
                }
    
                $net_b = $this->inet_to_bits($net_n);
    
                $subnet = substr($net, $pos+1);
                if (substr($ip_b, 0, $subnet) === substr($net_b, 0, $subnet)) {
                    return true;
                }
            }
        }
    
        return false;
    }

    /**
     * Registers a callback function for a given event
     *
     * @param Doku_Event_Handler $controller DokuWiki's event controller object
     * @return void
     */
    public function register(Doku_Event_Handler $controller) {
        $controller->register_hook('AUTH_ACL_CHECK', 'AFTER', $this, 'handle_auth_acl_check');
    }

    /**
     * [Custom event handler which performs action]
     *
     * @param Doku_Event $event  event object by reference
     * @param mixed      $param  [the parameters passed as fifth argument to register_hook() when this
     *                           handler was registered]
     * @return void
     */

    public function handle_auth_acl_check(Doku_Event &$event, $param) {
        $id     =& $event->data['id'];
        $user   =& $event->data['user'];
        $groups =& $event->data['groups'];

        if ($user) return;

        $networks = explode(' ', $this->getConf('trusted_ip'));
        if ($this->check_ip($_SERVER['REMOTE_ADDR'], $networks)) {
            $event->preventDefault();
            return;
        }

        $event->result = AUTH_NONE;
    }

}

// vim:ts=4:sw=4:et:
