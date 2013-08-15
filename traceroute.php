<?php

/**
 * This program is placed into the public domain.
 * 
 * New Traceroute objects have one optional parameter, hop query timeout, in
 * seconds. Default is 2.
 *
 * $tracer = new Traceroute();
 *
 * Traceroute objects have one public method, trace(). Calls to trace() require
 * one parameter, the target.
 *
 * $hops = $tracer->trace('sourceforge.net');
 *
 * Calls to trace() return a TracerouteResult object. By default, they
 * contain the target, the IP it resolved to, hop IPs and latencies as well
 * as hop count.
 *
 * TracerouteResult objects are accessed like arrays to retrieve hop
 * information. Hops are represented by associative arrays; use the actual
 * hop numbers as indexes. If there is more than one tailing timeout, they 
 * are truncated to one.
 *
 * print_r($hops[1]);
 * print_r($hops[2]);
 *
 * By default, 'ip' and 'rtt' are available. RDNS, ASN and geolocation info can
 * be loaded with the following methods:
 *
 * loadASN()  adds 'asn' and 'asn_desc' to hops
 * loadRDNS() adds 'rdns' to hops
 * loadGeo()  adds 'city', 'region', 'country', 'lat', 'long' to hops
 *
 * To retrieve the target and target IP, use the target() and targetIP()
 * methods. Number of hops can be retrieved with numHops().
 *
 * The PECL geoip extension and Maxmind city and country databases are
 * required to retrieve geolocation info:
 *
 * http://pecl.php.net/package/geoip
 * http://dev.maxmind.com/geoip
 *
 * Access to exec(), whois, netcat and outbound TCP port 43 are required to
 * retrieve ASN info:
 *
 * http://www.team-cymru.org/Services/ip-to-asn.html#whois
 *
 * See example usage at the end of this file.
 *
 */

class TracerouteResult implements ArrayAccess
{
  protected $_asn;
  protected $_geo;
  protected $_hops;
  protected $_num_hops;
  protected $_rdns;
  protected $_target;
  protected $_target_ip;

  public function __construct($target, $target_ip, $hops)
  {
    $this->_asn = 0;
    $this->_geo = 0;
    $this->_hops = $hops;
    $this->_num_hops = count($hops);
    $this->_rdns = 0;
    $this->_target = $target;
    $this->_target_ip = $target_ip;
  }

  public function offsetExists($offset)
  {
    if (array_key_exists($offset, $this->_hops)):
      return TRUE;
    else:
      return FALSE;
    endif;
  }

  public function offsetGet($offset)
  {
    return $this->_hops[$offset - 1];
  }

  public function offsetSet($offset, $value)
  {
    $this->_hops[$offset - 1] = $value;
  }

  public function offsetUnset($offset)
  {
    $this->_hops[$offset - 1] == NULL;
  }

  public function numHops()
  {
    return $this->_num_hops;
  }

  public function target()
  {
    return $this->_target;
  }

  public function targetIP()
  {
    return $this->_target_ip;
  }

  public function loadASN()
  {
    if (!$this->_asn):
      $ip_list = '';

      for ($i = 0; $i < $this->_num_hops; $i++):
        $ip_list .= '-f '.$this->_hops[$i]['ip']."\n";
      endfor;

      # http://http://www.team-cymru.org/Services/ip-to-asn.html#whois
      exec('echo -e "'.rtrim($ip_list, "\n").'" | nc whois.cymru.com 43',
                             $output, $retval);

      if ($retval > 0):
        throw new Exception('loadASN(): '.implode("\n", $output));
      endif;

      for ($i = 0; $i < $this->_num_hops; $i++):
        if ($this->_hops[$i]['ip'] !== NULL):
          $fields = explode('|', $output[$i]);
          $fields[0] = trim($fields[0]);
          $fields[2] = trim($fields[2]);

          if ($fields[0] !== 'NA'):
            $this->_hops[$i]['asn'] = $fields[0];
            $this->_hops[$i]['asn_desc'] = $fields[2];
          else:
            $this->_hops[$i]['asn'] = NULL;
            $this->_hops[$i]['asn_desc'] = NULL;
          endif;
        else:
          $this->_hops[$i]['asn'] = NULL;
          $this->_hops[$i]['asn_desc'] = NULL;
        endif;
      endfor;

      $this->_asn = 1;
    endif;
  }

  public function loadGeo()
  {
    if (!is_callable('geoip_record_by_name')):
      throw new Exception('loadGeo(): geoip extension not loaded');
    endif;

    if (!$this->_geo):
      for ($i = 0; $i < $this->_num_hops; $i++):
        if ($this->_hops[$i]['ip'] !== NULL):
          # the free database is mostly terrible
          $info = geoip_record_by_name($this->_hops[$i]['ip']);

          $this->_hops[$i]['city'] = $info['city'];
          $this->_hops[$i]['region'] = $info['region'];
          $this->_hops[$i]['country'] = $info['country_code'];

          if ($this->_hops[$i]['city']):
            $this->_hops[$i]['lat'] = $info['latitude'];
            $this->_hops[$i]['long'] = $info['longitude'];
          else:
            $this->_hops[$i]['lat'] = NULL;
            $this->_hops[$i]['long'] = NULL;
          endif;
        else:
          $this->_hops[$i]['city'] = NULL;
          $this->_hops[$i]['region'] = NULL;
          $this->_hops[$i]['country'] = NULL;
          $this->_hops[$i]['lat'] = NULL;
          $this->_hops[$i]['long'] = NULL;
        endif;
      endfor;

      $this->_geo = 1;
    endif;
  }

  public function loadRDNS()
  {
    if (!$this->_rdns):
      for ($i = 0; $i < $this->_num_hops; $i++):
        if ($this->_hops[$i]['ip'] !== NULL):
          $rdns = gethostbyaddr($this->_hops[$i]['ip']);

          if ($rdns !== $this->_hops[$i]['ip']):
            $this->_hops[$i]['rdns'] = $rdns;
          else:
            $this->_hops[$i]['rdns'] = NULL;
          endif;
        else:
          $this->_hops[$i]['rdns'] = NULL;
        endif;
      endfor;

      $this->_rdns = 1;
    endif;
  }
}

class Traceroute
{
  protected $_timeout;

  public function __construct($timeout = 2)
  {
    if (!is_callable('exec')):
      throw new Exception('__construct(): exec() not available');
    endif;

    $this->_timeout = escapeshellarg($timeout);
  }

  public function trace($target)
  {
    exec("/bin/traceroute -n -N30 -q1 -w{$this->_timeout} ".
         escapeshellarg($target).' 2>&1', $output, $retval);

    if ($retval > 0):
      throw new Exception('trace(): '.implode("\n", $output));
    endif;

    $num_lines = count($output);

    # split output lines into arrays delimited by whitespace
    for ($i = 0; $i < $num_lines; $i++):
      $output[$i] = preg_split('/\s+/', trim($output[$i]));
    endfor;

    $target_ip = trim($output[0][3], '(),');

    array_shift($output);

    $num_lines = $num_lines - 1;
    $tail_timeouts = 0;

    # get number of tail timeouts
    for ($i = $num_lines; $i > 0; $i--):
      if ($output[$i - 1][1] === '*'):
        $tail_timeouts++;
      else:
        break;
      endif;
    endfor;

    # truncate to one tail timeout if more than one
    if ($tail_timeouts > 1):
      $output = array_slice($output, 0, 30 - ($tail_timeouts - 1));
    endif;

    $num_lines  = count($output);

    # pack info into associative arrays
    for ($i = 0; $i < $num_lines; $i++):
      if ($output[$i][2]):
        $output[$i] = array('ip' => trim($output[$i][1]),
                            'rtt' => round($output[$i][2]));
      else:
        $output[$i] = array('ip' => NULL, 'rtt' => NULL);
      endif;
    endfor;

    return new TracerouteResult($target, $target_ip, $output);
  }
}

### example usage ###

$tracer = new Traceroute();

try {
  $hops = $tracer->trace('sourceforge.net');

  $hops->loadRDNS();
  $hops->loadASN();
  $hops->loadGeo();

  print $hops->target().' ('.$hops->targetIP().') in '.$hops->numHops().
        " hops:\n";

  for ($i = 1; $i <= $hops->numHops(); $i++):
    print_r($hops[$i]);
  endfor;

  exit(0);
} catch (Exception $e) {
  print "error: ".$e->getMessage()."\n";
  exit(1);
}

?>
