# Track the Data Flow 

### Wikimedia Exploration, Sep 28 2020 

1. First get the ICP 
2. Identify attribute or variable from the ICP
3. Track the variable or attribute upwards and downwards 
4. Search within the module 

#### Repository-1

`$http_host = '0.0.0.0'` ... no parsing error but `$http_host` is used as a default in `class cdh::hue(` that `inherits cdh::hue::defaults` 
Source: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/cdh4-2018-06/manifests/` ... `class cdh::hue` is in hue.pp and `cdh::hue::defaults` is in `hue/defaults.pp` 
In `class cdh::hue(`,  `user { 'hue'` is a true positive. 

> Will need cross script tracking. TODO. 

#### Repository-2 

In `cdh::oozie`, `$url` is has a valid insecure HTTP, but is not used to setup a server, rather used in 
`content => "# NOTE:  This file is managed by Puppet. export OOZIE_URL='${url}'",` ... note the usage of ${url} ...
access to a variable. 
In `cdh::oozie` ... oozie.pp resides in `/Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/cdh4-2018-06/manifests/`

> Has been addressed in TaintPup 

#### Repository-3

A hard-coded password `$jdbc_password = 'oozie'` is specified in `cdh::oozie::defaults`, located in `oozie/defaults`, which is used in 
`cdh::oozie::server` as `$jdbc_password = $cdh::oozie::defaults::jdbc_password`, which is not used anywhere later. 

> Has been addressed in TaintPup 


#### Repository-4

In `cdh::hive::metastore::mysql` using `command`, an actual user password us used. See below: 

```
command => "/usr/bin/mysql ${username_option} ${password_option} -e \"
CREATE USER '${db_user}'@'localhost' IDENTIFIED BY '${db_pass}';
CREATE USER '${db_user}'@'127.0.0.1' IDENTIFIED BY '${db_pass}';
GRANT ALL PRIVILEGES ON ${db_name}.* TO '${db_user}'@'localhost' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON ${db_name}.* TO '${db_user}'@'127.0.0.1' WITH GRANT OPTION;
FLUSH PRIVILEGES;\"",

```

`$db_pass = $cdh::hive::jdbc_password`, meaning $db_pass comes from `cdh::hive::`, which in turn comes from `$jdbc_password = $cdh::hive::defaults::jdbc_password,` 
in `cdh::hive::defaults`. there is hard-coded password for `$jdbc_password` i.e. `$jdbc_password = 'hive'`. 


> Will need cross script tracking. TODO. 

#### Repository-5 

  
Variables or attributes that have HTTP URL first needs to be checked for HTTPS. If exists then report, 
otherwise do not. 
`location  => "http://repos.mesosphere.io/` and `source  => "http://repos.mesosphere.io/el/${osrel}/noarch/RPMS/`
are examples in `/Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/mesos-2018-06/manifests/repo.pp` (`class mesos::repo`).

> Has been addressed in TaintPup 

 
#### Repository-6 

In `class nginx::ssl` located in `/Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/nginx-2018-06`
uses a template file using `template()` for `file{}` `content => template('nginx/ssl.conf.erb')`.
The ERB file has a hard-coded SSL cipher that is an example of a hard-coded secret. 
So we need to check for SSL cipher or SSH keys in ERB files as well. 

> Upon further inspection the content of the template file is not a hard-coded secret , rather what ciphers need to be enabled. We will not tackle this. 


### Openstack Exploration, Sep 30 2020 

#### Repository-1

Location: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-ec2api-2018-06/sync.pp`

Hard-coded user name (`$system_user = 'ec2api'`) propagated from paramters into the `exec`
`user => $system_user`. 

> Has beed addressed in TaintPup 


#### Repository-2 

Location: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-ec2api-2018-06/postgresql.pp`

Hard-coded user name (`$user = 'ec2api'`) propagated from parameters into the 
`::openstacklib::db::postgresql {` body of `password_hash => postgresql_password($user, $password)`. 

> Has beed addressed in TaintPup 

#### Repository-3

Location: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-ec2api-2018-06/mysql.pp`

Hard-coded user name (`$user = 'ec2api'`) propagated from parameters into the 
`::openstacklib::db::mysql {` body of `user => $user,`. 

> Has beed addressed in TaintPup 

#### Repository-4 

Location: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-ec2api-2018-06/`

Insecure HTTP used in `keystone/auth.pp` (`$public_url = 'http://127.0.0.1:8788'`). Propagates to
`keystone::resource::service_identity` (`public_url => $public_url`). 

> Has beed addressed in TaintPup 


#### Repository-5

Location: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-plumgrid-2018-06/deployment_scripts/puppet/manifests/plumgrid_nova_compute.pp` 

Example false positives that can be mitigated using a parser: 
> $admin_password = try_get_value($neutron_config, 'keystone/admin_password')
> $admin_identity_protocol = get_ssl_property($ssl_hash, {}, 'keystone', 'admin', 'protocol', 'http')

Another example:
> $nova_hash = hiera_hash('nova', {})
> $nova_sql_password = pick($nova_hash['db_password'])
> line => "connection = mysql://nova:$nova_sql_password@$mgmt_vip/nova?read_timeout=60", in `file {}` 

Another example: 
> $neutron_config  = hiera_hash('quantum_settings', {})
> $metadata_secret = pick($neutron_config['metadata']['metadata_proxy_shared_secret'], 'root')
> $neutron_db_password = $neutron_config['database']['passwd']
> $neutron_db_user = pick($neutron_config['database']['user'], 'neutron')

Another example: 
> $access_hash = hiera_hash('access', {})
> $admin_username = pick($access_hash['user'])
> $admin_password = pick($access_hash['password'])

Another example:
> password_hash => mysql_password($password),
> password_hash => postgresql_password($user, $password),

Another example:
> $configure_user = true,


> Has beed addressed in TaintPup 

#### Repository-6

Location:`/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-plumgrid-2018-06/deployment_scripts/puppet/modules/plumgrid/manifests/init.pp`

`class plumgrid` is a class that `inherits plumgrid::params` means a class needs sth. that comes from 
`params.pp` which is `plumgrid/manifests/` 

Also, `$rest_ip = '0.0.0.0',` is not used anywhere in the module (`plumgrid/`) 


> First part will need cross script tracking. Second part addressed in TaintPup 

#### Repository-7

Location:`/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-plumgrid-2018-06/deployment_scripts/puppet/modules/plumgrid/manifests`

> $lxc_data_path = '/var/lib/libvirt/filesystems/plumgrid-data'
> target => "${lxc_data_path}/root/.ssh/authorized_keys" 

This is not detected by SLIC ... needs better parsing 

> Upon further inspection we see that even though the path of the less are exposed, they are not hard-coded secrets as there is not way to know unless we have permissions of the folder. We will skip this. 

#### Repository-8

Location:`/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-heat-2018-06/manifests/keystone/auth_cfn.pp`

Example of insecure HTTP being assigned 

> keystone::resource::service_identity{ 
> $public_url           = 'http://127.0.0.1:8000/v1',
> $admin_url            = 'http://127.0.0.1:8000/v1',
> $internal_url         = 'http://127.0.0.1:8000/v1',
> public_url          => $public_url,
> admin_url           => $admin_url,
> internal_url        => $internal_url,

> Addressed in TaintPup 

#### Repository-9

Location:`/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-heat-2018-06/example/site.pp`

Nice examples on how the modules inside `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-heat-2018-06/manifests/` are used: 

1. Let us consider the following: 
>  class { '::heat::db::mysql':
>    password => 'heat',
>  }

`heat` will be propagated into `class heat::db::mysql` as `$password`.
Then used in `password_hash => mysql_password($password),` within `::openstacklib::db::mysql {`
inside `class heat::db::mysql` 

So if we have a script that looks like above then we can get a full flow of information of 
data `heat`


2. Let us consider sth. else: 
>  class { '::heat::keystone::authtoken':
>    password => 'password',
>  }

`password` will be propagated into `heat::keystone::authtoken(){}` as `$password`.
Then used in `password => $password,` within `keystone::resource::authtoken {}`
inside `class heat::keystone::authtoken(){}` 

So if we have a script that looks like above then we can get a full flow of information of 
data `password` 

3. Finally, let us consider this:
>  class { '::heat::engine':
>    auth_encryption_key => 'whatever-key-you-like',
>  }

`whatever-key-you-like` will be propagated into `class heat::engine(){}` as `$auth_encryption_key,`.
Then used in `$param_size = size($auth_encryption_key)` and `'DEFAULT/auth_encryption_key': value => $auth_encryption_key, secret => true;` resptecively, within `class heat::engine (){}` and `heat_config {}`
inside `class heat::engine (){}` 

So if we have a script that looks like above then we can get a full flow of information of 
data `whatever-key-you-like` 

> Will need cross-script tracking. TODO 

#### Repository-10 

Location: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-neutron-2018-06` 

1. In `manifests/agents/ml2/networking_baremetal.pp` ,   `$auth_url` ('http://127.0.0.1:35357') is propagated into `ironic_neutron_agent_config {}` as `'ironic/auth_url': value => $auth_url;`

2. In `manifests/agents/ml2/networking_baremetal.pp` , `$password` propagated into `ironic_neutron_agent_config {}` as `'ironic/password': value => $password;`

3. In `manifests/agents/ovn_metadata.pp`, `$auth_ca_cert`, `$shared_secret`, `$nova_client_cert`  are propagated into 

>  'DEFAULT/auth_ca_cert':                   value => $auth_ca_cert;
>  'DEFAULT/metadata_proxy_shared_secret':   value => $shared_secret;
> 'DEFAULT/nova_client_cert':               value => $nova_client_cert;

Need to check how these (`$auth_ca_cert`, `$shared_secret`, `$nova_client_cert`) values are assigned. 
Similar things happen in `manifests/agents/ml2/metadata.pp`  

4. `content => template('neutron/n1kv.conf.erb'),` in `n1kv_vem.pp`. Need to check content of the ERB file 

5. In `manifests/agents/l2gw.pp` , `$l2_gw_agent_priv_key_base_path, $l2_gw_agent_cert_base_path, $l2_gw_agent_ca_cert_base_path`

> 'ovsdb/l2_gw_agent_priv_key_base_path':     value => $l2_gw_agent_priv_key_base_path;
> 'ovsdb/l2_gw_agent_cert_base_path':         value => $l2_gw_agent_cert_base_path;
> 'ovsdb/l2_gw_agent_ca_cert_base_path':      value => $l2_gw_agent_ca_cert_base_path;

Need to check where `$l2_gw_agent_priv_key_base_path, $l2_gw_agent_cert_base_path, $l2_gw_agent_ca_cert_base_path` is coming from. 

6. In `manifests/agents/dhcp.pp`, `$ovsdb_agent_ssl_key_file , $ovsdb_agent_ssl_cert_file, $ovsdb_agent_ssl_ca_file` used in `neutron_dhcp_agent_config {}` and `$req_ssl_opts = {}` 

Need to check where `$ovsdb_agent_ssl_key_file , $ovsdb_agent_ssl_cert_file, $ovsdb_agent_ssl_ca_file` is coming from. 

7. In `manifests/db/postgresql.pp` , `$password,` propagates into `password_hash => postgresql_password($user, $password),` ... this function gives hash , not plain password. `$user ` propagates into `::openstacklib::db::postgresql {` as `user => $user,`

8. In `manifests/db/mysql.pp` , `$password,` propagates into `password_hash => mysql_password($password),` ... this function gives hash , not plain password. `$user ` propagates into `::openstacklib::db::postgresql {` as `user => $user,`

9. In `manifests/keystone/auth.pp` we see 

>  $password,
>  $public_url          = 'http://127.0.0.1:9696',
>  $admin_url           = 'http://127.0.0.1:9696',
>  $internal_url        = 'http://127.0.0.1:9696',

later being used in `keystone::resource::service_identity {}` as 

> password            => $password,
> public_url          => $public_url,
> admin_url           => $admin_url,
> internal_url        => $internal_url,

No function call ... all plain text 

10. In `manifests/keystone/authtoken.pp` we see 

>  $username                       = 'neutron',
>  $password                       = $::os_service_default,
>  $auth_url                       = 'http://localhost:5000',
>  $www_authenticate_uri           = 'http://localhost:5000',

later being used in `keystone::resource::authtoken {}` as 

>    username                       => $username,
>    password                       => $password,
>    auth_url                       => $auth_url,
>    www_authenticate_uri           => $www_authenticate_uri_real,

11. In `manifests/plugins/ovs/opendaylight.pp`, `$odl_username, $odl_password, $odl_check_url` was used in 

>  command   => "${curl_post} -u ${odl_username}:${odl_password} -d '${rest_data}' ${cert_rest_url}",
>  unless    => "${curl_get} -u ${odl_username}:${odl_password} -d '${rest_get_data}' ${cert_rest_get} | grep -q ${cert_data}",
>  command   => "curl -k -o /dev/null --fail --silent --head -u ${odl_username}:${odl_password} ${odl_check_url_parsed}",

Need to see how the values of `$odl_username, $odl_password, $odl_check_url` are flowing 

12. In `manifests/plugins/plumgrid.pp`,  `$connection, $admin_password, $auth_protocol, $l2gateway_sw_username, $l2gateway_sw_password`  
 is  used in 

> 'PLUMgridDirector/username':             value => $username;
> 'PLUMgridDirector/password':             value => $password, secret =>true;
> 'l2gateway/sw_username':                 value => $l2gateway_sw_username;
> 'l2gateway/sw_password':                 value => $l2gateway_sw_password, secret =>true;

and 

> 'keystone_authtoken/admin_user' :                value => 'admin';
> 'keystone_authtoken/admin_password':             value => $admin_password, secret =>true;

hard-coded user name. 

Similar things are observed in `manifests/plugins/opencontrail.pp`, for `$keystone_admin_user, $keystone_admin_tenant_name,$keystone_admin_password, $keystone_admin_token` in `neutron_plugin_opencontrail {}` 

Similar things happen in `manifests/plugins/nvp.pp`, for `$nvp_user, $nvp_password,` in `neutron_plugin_nvp {}`

Similar things happen on `manifests/plugins/nuage.pp` for `$nuage_vsd_username, $nuage_vsd_password,` in `'RESTPROXY/serverauth': value => "{nuage_vsd_username}:${nuage_vsd_password}";`

Similar things happen in `manifests/plugins/nsx.pp`, for `$nsx_api_user, $nsx_api_password` in `neutron_plugin_nsx {}`

Similar things happen in `manifests/plugins/midonet.pp`, for `$keystone_username, $keystone_password` in `neutron_plugin_midonet {}`

Similar things happen in `manifests/plugins/cisco.pp` for 
- `$database_user, $database_pass` in `neutron_plugin_cisco_db_conn {}`
- `$keystone_username, $keystone_password, $keystone_auth_url` in `neutron_plugin_cisco_credentials {}`

Similar things happen in `manifests/server/notifications.pp`, for `$auth_url, $username, $password` in `neutron_config {}`

Similar things happen in `manifests/server/placement.pp`, for `$auth_url, $username, $password` in `neutron_config {}`

Similar things happen in `manifests/services/lbaas/octavia.pp`, for `$base_url, $auth_url, $admin_user, $admin_password` in `neutron_config {}`

Similar things happen in `manifests/wsgi/api.pp`, for `$ssl_cert, $ssl_crl_path` in `::openstacklib::wsgi::apache {}`

Similar things happen in `manifests/rootwrap.pp`, for `$xenapi_connection_username, $xenapi_connection_password` in `:neutron_rootwrap_config {} `

###### Slightly unrelated: `$quota_firewall_policy,$$quota_router,$quota_security_group_rule,$quota_firewall_rule `  need to see this flows to and from `manifests/quota.pp` ... later used in `neutron_config {}`

Similar things happen in `manifests/init.pp` for `$amqp_username, $amqp_password` in `oslo::messaging::amqp {}`
Similar things happen in `manifests/init.pp` for `$kombu_ssl_certfile, $kombu_ssl_keyfile` in `oslo::messaging::rabbit {}`
Similar things happen in `manifests/designate.pp`, for `$auth_url, $username, $password` in `neutron_config {}`

##### Tracking data 

1. `examples/neutron.pp`: `password => 'secrete',` in `class { '::neutron::server::notifications':` calls `manifests/server/notifications.pp` with `password` that flows into `neutron_config {}` 

2. `examples/cisco_ml2.pp`: 
```
class {'::neutron::plugins::ml2::cisco::ucsm':
  ucsm_username  => 'admin',
  ucsm_password  => 'password',
}  
```
calls `manifests/plugins/ml2/cisco/uscm.pp` with `ucsm_username` and `ucsm_password` that flows into ` neutron_plugin_ml2 {}` 

3. In `manifests/plugins/ml2/cisco/uscm.pp` 

```
  nexus_config             => {
    'n9372-1' => {
      'username'     => 'admin',
      'password'     => 'password',
    },
    'n9372-2' => {
      'username'     => 'admin',
      'password'     => 'password',
    }, 
  }
```

`username` and `password`  flows within `$nexus_config,` into `class neutron::plugins::ml2::cisco::nexus(){}` in `manifests/plugins/ml2/cisco/nexus.pp`

> Validation with TaintPup done for single script taint tracking. Need to do cross script tracking .... TODO. 
> During cross script tracking please see /Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-neutron-2018-06/manifests/plugins/nvp.pp as username and password
> flows from the outside to a resource 
> Double check if $::os_service_default is coming from external library or Puppet file or other config file 


#### Repository-11 

1. Location:`/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-ceilometer-redis-2018-06/deployment_scripts/puppet/modules/redis/tests/init.pp`, `conf_bind => '0.0.0.0'`, used in `init.pp` is used no where ... this is a false positive 

> Actually it is a true positive as 0.0.0.0 is assigned than attribute meaning it will be executed . Addressed in TaintPup. 

#### Repository-12

Location:`/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-monasca-2018-06/` 

1. In `manifests/vertica/config.pp`,  `$db_admin_password` is declared but not assigned, so this will be a FP 

2. In `manifests/vertica/config.pp`,  `$db_user` is declared and used inside `file {}`, using `owner  => $db_user,` 

3. In `manifests/storm/config.pp`,  `$mirror = 'http://apache.arvixe.com/storm',` is used in `wget::fetch { "${mirror}/${storm_version}/${tarfile}": }`

4. In `manifests/storm/config.pp`,  `$storm_user` is used in `storm_user => $storm_user` and `user { $storm_user:` and `owner => $storm_user,` and `exec { "tar -xvzf /${cache_dir}/${tarfile}":`

5. In `manifests/storm/config.pp`,  `$storm_user` is declared but not assigned, so this will be a FP  

6. In `manifests/persister/config.pp`,  `$db_admin_password` is declared but not assigned, so this will be a FP  

7. In `manifests/keystone/auth.pp`, `$role_user` is used in `keystone_role { }` and `$real_user_roles_user = [$role_user]` 

8. In `manifests/influxdb/bootstrap.pp`, `$influxdb_password` and `$influxdb_dbuser_ro_password` is used in `exec { "/tmp/${script}": environment => []}` 

9. In `manifests/db/mysql.pp`, `$sql_password` is used in `mysql::db { 'mon':}` which is a true positive 
and in `password_hash => mysql_password($sql_password),` si a false positive 

10. In `manifests/checks/instances/solidfire.pp`, `$admin_password` and `$admin_password` is declared but not used in so this is a false positive 

11. In `manifests/checks/instances/rabbitmq.pp`, `$rabbitmq_user` and `$rabbitmq_pass` is declared but not used in so this is a false positive 

12. In `manifests/checks/instances/mysql.pp`, `$user` and `$pass` is declared but not used in so this is a false positive 

13. In `manifests/checks/instances/http_check.pp`, `$username` and `$password` is declared but not used in so this is a false positive 

14. In `manifests/checks/vertica.pp`, `$user` and `$password` is declared but not used in so this is a false positive  

15. In `manifests/checks/ovs.pp`, `$admin_user` and `$admin_password` is declared but not used in so this is a false positive  

16. In `manifests/checks/libvert.pp`, `$admin_user` and `$admin_password` is declared but not used in so this is a false positive  

17. In `manifests/checks/libvert.pp`, `$admin_user` and `$admin_password` is declared but not used in so this is a false positive  

18. In `manifests/thresh.pp`, `$thresh_fetch_url` is used in `wget::fetch { "${thresh_fetch_url}/${mon_thresh_build_ver}/${mon_thresh_deb}":}` 

18. In `manifests/persister.pp`, `$db_admin_password` is declared but not used and  `pers_fetch_url` is used in `wget::fetch { "${pers_fetch_url}/${mon_pers_build_ver}/${mon_pers_deb}":`

19. In `manifests/params.pp`, `$agent_password`, `$admin_password`, `$admin_name`, `$user_name` is declared but not used ... `database_url` is a true positive 

20. In `manifests/notification.pp`, `$smtp_password` and `$smtp_user` is declared but not assigned, so FP 

21. In `manifests/api.pp`, `$api_user` is used in `owner => $api_user,` and ` user { $api_user:}`

22. In `manifests/alarmdefs.pp`, `$admin_username` and `$admin_password` is used in `environment => []`

23. In `manifests/agent.pp`, `$password` and `$username` is declared but not assigned, so FP 

> Addressed by TaintPup

#### Repository-13

Location:`/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-mellanox-2018-06/` 

1. In `deployment_scripts/puppet/manifests` using `'sdn/password': value => "${neo_password}";`  user names and passwords are used but they come from hiera (`$mlnx = hiera('mellanox-plugin')` and `  $neo_password = $mlnx['mlnx_neo_password']`). 

> Addressed by TaintPup

#### Repository-14

Location:`/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-vitrage-2018-06/` 

1. In `manifests/db/mysql.pp` using password is not hard-coded as `password_hash => mysql_password($password),` is used ... user name is used `user => $user,` that comes from `$user = 'vitrage',`. Need to track how $user propagates. Similar thing for `manifests/db/postgresql.pp`.  

2. In `manifests/keystone/auth.pp`, $passowrd is used with `password => $password,` and $auth_name is used with `auth_name => $auth_name,`. Similar for $public_url, $admin_url, $internal_url that uses HTTP. 

3. In `manifests/keystone/authtoken.pp`, $passowrd is used with `password => $password,` and $username is used with `username => $username,` and `auth_url => $auth_url,`. Need to track $password, $username, $auth_url.   

4. In `manifests/wsgi/apache.pp`, $ssl_certs_dir is used with `ssl_certs_dir => $ssl_certs_dir,` and $ssl_crl_path is used with `ssl_crl_path => $ssl_crl_path,`. Need to track $ssl_crl_path, $ssl_crl_path.  

5. In `manifests/init.pp`, need to track $amqp_ssl_ca_file, $amqp_ssl_cert_file, $amqp_ssl_key_file, $amqp_ssl_key_password, $amqp_username, $amqp_password as they are used and assigned. 

6. In `manifests/auth.pp`, need to track $auth_url, $auth_user, $auth_password as they are used and assigned. 

7. In `manifests/api.pp`, need to track $host as it is used and assigned (`$host = '0.0.0.0'` and `'api/host' : value => $host;`). 

8. In `examples/vitrage.pp`, `class { '::vitrage::keystone::auth':}` calls `manifests/keystone/auth.pp` with 

```
  admin_url    => 'http://127.0.0.1:8999',
  internal_url => 'http://127.0.0.1:8999',
  public_url   => 'http://127.0.0.1:8999',
  password     => 'a_big_secret',
```

which is propagated into `keystone::resource::service_identity {}` in `manifests/keystone/auth.pp` 



9. In `examples/vitrage.pp`, `class { '::vitrage::api':}` calls `manifests/api.pp`, but the specifed paramers mentioned below go nowhere 

```
  keystone_password     => 'a_big_secret',
  keystone_identity_uri => 'http://127.0.0.1:35357/',
```

10. In `examples/vitrage.pp`, `class { '::vitrage::auth':}` calls `manifests/auth.pp`, with parameters below 

```
  auth_password => 'a_big_secret',
```
that is propagated into `vitrage_config {}` in `manifests/auth.pp`

> Except for cross script tracking handled by TaintPup 

#### Repository-15

Location:`/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/solar-resources-2018-06/resources/` 

1. In `nova_puppet/1.0.0/actions/remove.pp` hard-coded password `rabbit_password    => 'not important as removed',`  

2. in `node_network_puppet/1.0.0/actions/remove.pp` there is a hard-coded password `auth_password   => 'not important as removed',` . Similar for a hard-coded password in `neutron_puppet/1.0.0/actions/remove.pp (rabbit_password   => 'not important as removed',)` 

3. True positive in `neutron_agents_metadata_puppet/1.0.0/actions/run.pp` ... example: `auth_url => "http://${auth_host}:${auth_port}/v2.0",`

4. True positive in `glance_registry_puppet/1.0.0/actions/remove.pp` ... example: `keystone_password => 'not important as removed'`. Also in `cinder_puppet/1.0.0/actions/remove.pp` as `rabbit_password => 'not important as removed',`. Also in `cinder_api_puppet/1.0.0/actions/remove.pp` as `keystone_password  => 'not important as removed',`


4. In `nova_puppet/1.0.0/actions/run.pp` even though used, $qpid_password, $rabbit_password, $db_password, $db_user comes from hiera()  .. so not hard-coded password. Similarly for $neutron_admin_password and $neutron_admin_username in `nova_neutron_puppet/1.0.0/actions/run.pp`. Similar for $libvirt_inject_password in `nova_compute_libvirt_puppet/1.0.0/actions/update.pp` and `nova_compute_libvirt_puppet/1.0.0/actions/run.pp`. Similar for $admin_user and $admin_password in `nova_api_puppet/1.0.0/actions/update.pp` and `nova_api_puppet/1.0.0/actions/run.pp`. Similarly in `node_network_puppet/1.0.0/actions/run.pp`, $db_user, $db_password, $auth_user, $auth_password are used but data comes from hiera, so not a hard-coded password. Similar for $qpid_username, $qpid_password, $rabbit_password in `neutron_puppet/1.0.0/actions/run.pp`. Similar for $auth_user, $auth_password in `neutron_agents_metadata_puppet/1.0.0/actions/run.pp`. Similarly for `$ha_vrrp_auth_password` in `neutron_agents_l3_puppet/1.0.0/actions/run.pp`. Similar for $db_user and $db_password in `keystone_puppet/1.0.0/actions/run.pp` used as `database_connection  => "mysql://$db_user:$db_password@$db_host:$db_port/$db_name",`. Similar for $db_user and $db_password and $keystone_password and $keystone_user in `glance_registry_puppet/1.0.0/actions/run.pp` and `glance_registry_puppet/1.0.0/actions/update.pp` in `glance_registry_puppet/1.0.0/actions/update.pp`

> Handled by TaintPup 

#### Repository-15

Location: ``

> $mysql_opts = hiera('mysql')
> $mysql_password = $mysql_opts['root_password']
> $sql_connect = "mysql -h ${galera_host} -uroot -p${mysql_password}"
... 
> $sql_query = "${sql_connect} -e \"${db_query}; ${table_query}; ${update_query};\""

Even though there is a SQL-injection like statement, the value is not hard-coded rather coming
from hiera(). This should not be flagged. 

> Handled by TaintPup 


#### Repository-16

Location: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-scaleio-2018-06/deployment_scripts/puppet/manifests/nova.pp`

```
if $scaleio['existing_cluster'] {
    $client_password = $password
  } else {
    $client_password_str = base64('encode', pw_hash($password, 'SHA-512', 'scaleio.client.access'))
    $client_password = inline_template('Sio-<%= @client_password_str[33..40] %>-<%= @client_password_str[41..48] %>')
}
```

`client_password` later used in `class {'::scaleio_openstack::nova':}` as `gateway_password`

> Handled by TaintPup 

#### Repository-17

Location: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-scaleio-2018-06/deployment_scripts/puppet/manifests/cluster.pp`

> $client_password_str = base64('encode', pw_hash($password, 'SHA-512', 'scaleio.client.access'))
> $client_password = inline_template('Sio-<%= @client_password_str[33..40] %>-<%= @client_password_str[41..48] %>')

after >50 lines later used as 

```
        scaleio::cluster {'Create scaleio client user':
          ensure          => 'present',
          client_password => $client_password,
          require         => [Protection_domain_ensure[$protection_domain_array], Sds_ensure[$to_add_sds_names]],
        }
```

in `scaleio::login {'Normal':}`

> Handled by TaintPup 


#### Repository-18

Location: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-aodh-2018-06/examples/aodh.pp`

One example: 
```
class { '::aodh::keystone::authtoken':
  password => 'a_big_secret',
}
```
^ this will call `$password` in `class aodh::keystone::authtoken(){}` ... that is later used 
as `password => $password,` in `keystone::resource::authtoken { 'aodh_config':}`

Another example: 
```
class { '::aodh::auth':
  auth_password => 'a_big_secret',
}
```

`$auth_password` called in `class aodh::auth (){}` and later used as
`'service_credentials/password' : value => $auth_password, secret => true;` in `aodh_config {}` 

> TODO. Need to be handled by TaintPup 


#### Repository-19

Location: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-pacemaker-2018-06/`

1. In `manifests/new/params.pp`  `$cluster_password` is assigned a value but not used 
2. In `manifests/stonith/fence_wti.pp` and `manifests/stonith/fence_vmware_soap.pp` and `manifests/stonith/fence_rsb.pp` and `manifests/stonith/fence_ipmilan.pp`. `manifests/stonith/fence_ipdu.pp`, `manifests/stonith/fence_intelmodular.pp`, `manifests/stonith/fence_imm.pp`, `manifests/stonith/fence_ilo4.pp`, `manifests/stonith/fence_ilo3.pp`, `manifests/stonith/fence_ilo2.pp`, `manifests/stonith/fence_ilo.pp`, `manifests/stonith/fence_ilomp.pp`, `manifests/stonith/fence_ifmb.pp`, `manifests/stonith/fence_idrac.pp`, `manifests/stonith/fence_ibmblade.pp`, `manifests/stonith/fence_hpblade.pp`, `manifests/stonith/fence_eps.pp`, `manifests/stonith/fence_eaton_snmp.pp`, `manifests/stonith/fence_drac5.pp`, `manifests/stonith/fence_compute.pp`, `manifests/stonith/fence_cisco_ics.pp`, `manifests/stonith/fence_cisco_mds.pp`, `manifests/stonith/fence_brocade.pp`, `manifests/stonith/fence_bladecenter.pp`,`manifests/stonith/fence_aps.pp`, `manifests/stonith/fence_apc_snmp.pp`,  `manifests/stonith/fence_rvhem.pp`,  `default => "passwd=\"${passwd}\"",` is an example of `$passwd` being used. 

3. In `manifests/stonith/fence_ironic.pp` and `manifests/stonith/fence_amt.pp` , `default => "password=\"${password}\""` is an example of `$password` being used  

4. In `manifests/params.pp` `$hacluster_pwd` has a value that is never used 

5. In `manifests/new.pp` , `$cluster_password` is   a hard-coded password that is used 

> Handled by TaintPup 

#### Repository-20

Location: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-octavia-2018-06/`

1. In `manifests/db/` , `mysql.pp` and `postgresql.pp` , `password_hash => postgresql_password($user, $password),` 
shows that the detected hard-coded passwords are FPs. However, $user is hard-coded and used as `user => $user,`

2. In `manifests/keystone/authtoken.pp` the following is used which are true positives 
```
    username                       => $username,
    password                       => $password,
    auth_url                       => $auth_url,
```

In `manifests/keystone/auth.pp` the following are also true positives: 
```
    public_url          => $public_url,
    internal_url        => $internal_url,
    admin_url           => $admin_url,
``` 

In `manifests/service_auth.pp` , `'service_auth/password' : value => $password;`, $password is used
Similar for `manifests/init.pp` 

> Handled by TaintPup 

#### Repository-21

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-purestorage-cinder-2018-06`

In `deployment_scripts/controller.pp`, `fc_passwd_1 => $plugin_settings["pure_password_1"],` is not a hard-coded password in `class { 'plugin_purestorage_cinder::controller' : }`. 
`$fc_passwd_1` is later is used in `class plugin_purestorage_cinder::controller (){}` as ` "${fabric_zone_1}/cisco_fc_fabric_password": value => $fc_passwd_1;`


> Handled by TaintPup 


#### Repository-22

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-manila-2018-06` 

1. In `manifests/backend/`, passwords are passed as parameters and being used for the following Puppet files: 

```
dellemc_isilon.pp
hitachi_hnas.pp
dellemc_unity.pp
dellemc_vmax.pp
dellemc_vnx.pp
netapp.pp
```

The syntax for passing passwords into any of the Puppet files is expressed as an example for *define manila::backend::dellemc_isilon (){}* and *define manila::backend::netapp (){}* below: 

```
manila::backend::dellemc_isilon { 'myBackend':
   driver_handles_share_servers  => false,
   emc_nas_login                 => 'admin',
   emc_nas_password              => 'password',
   emc_nas_server                => <IP address of isilon cluster>,
   emc_share_backend             => 'isilon',
}
```

```
manila::backend::netapp { 'myBackend':
   driver_handles_share_servers => true,
   netapp_login                 => 'clusterAdmin',
   netapp_password              => 'password',
   netapp_server_hostname       => 'netapp.mycorp.com',
   netapp_storage_family        => 'ontap_cluster',
   netapp_transport_type        => 'https',
}
```

Above is similar for `manifests/keystone/auth.pp` and `manifests/keystone/auth2.pp` and `manifests/share/netapp.pp` and `manifests/share/hitachi_hnas.pp` and `manifests/volume/cinder.pp` and `manifests/type.pp`, `manifests/type_set.pp`, `manifests/service_instance.pp` and `manifests/rabbitmq.pp` and `manifests/init.pp` 

2. In `manifests/network/neutron.pp` we see a password being used, but as class parameters `$neutron_admin_password = undef,` is undefined so not a true positive 

```
    'DEFAULT/neutron_admin_username':       value => $neutron_admin_username;
    'DEFAULT/neutron_admin_password':       value => $neutron_admin_password, secret => true;
    'DEFAULT/neutron_admin_auth_url':       value => $neutron_admin_auth_url;
```

> Handled by TaintPup ... if you have time after cross script tracking, then play with lists , how variables are propagated into lists, and then lists used in attributes 


#### Repository-24

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-congress-2018-06/` 

1. In `manifests/db/sync.pp`, `$user = 'congress',` is propagated into `exec { 'congress-db-sync':}` as `user => $user,`
2. In `manifests/db/mysql.pp`, `password_hash => mysql_password($password)` is a FP , so calling `congress::db::mysql{}` with `$password` is not a TP. Same for `manifests/db/postgresql.pp`
3. In `manifests/db/mysql.pp`, `$user = 'congress',` is propagated into `::openstacklib::db::mysql {}`, so TP. Same for `manifests/db/postgresql.pp`
4. In `manifests/keystone/auth.pp`, `$password` and `$auth_name` is propagated as `password => $password` and `auth_name => $auth_name,`. Same for `manifests/keystone/authtoken.pp`, also `$auth_url  = 'http://localhost:5000',` propagated into `keystone::resource::authtoken {}` 

> Handled by TaintPup 

#### Repository-25

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-rally-2018-06/` 

1. In `example/rally.pp`, `class { '::rally::settings': }` calls `manifests/settings.pp` and `class { '::rally': }`

> Need to do cross script tracking. TODO 

#### Repository-26

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/puppet-watcher-2018-06/` 

1. In `manifests/init.pp`, `$amqp_password = $::os_service_default,` is a false positive 

> Handled by TaintPup 

#### Repository-27

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/puppet-swift-2018-06/` 

1. In `manifests/keystone/auth.pp`, `$password`, `$public_url`, `$admin_url`, `$internal_url`, `$interna;_url3`, and `$auth_name` is propagated into `keystone::resource::service_identity {}` and `keystone::resource::service_identity {}`. Same for `manifests/keystone/dispersion.pp` as  `$auth_pass` propagated into `keystone_user {}` 

2. In `manifests/proxy/tempauth.pp`, `'user'    => 'admin',` is a TP. 
3. In `manifests/proxy/s3token.pp`, `$auth_uri = 'http://127.0.0.1:5000'` is a TP as it propagates into an if block as `$auth_uri_real = $auth_uri`.
4. In `manifests/proxy/tempauth.pp`, `'user'    => 'admin',` is a TP.   
5. In `manifests/proxy/ceilometer.pp`, `$auth_uri` and `$auth_url` propagates into   `swift_proxy_config {}` so TP
6. In `manifests/proxy/authtoken.pp`, the following makes sure that username and password is not hard coded: 

```
  $auth_url_real = pick($identity_uri, $auth_url)
  $username_real = pick($admin_user, $username)
  $project_name_real = pick($admin_tenant_name, $project_name)
  $password_real = pick($admin_password, $password)

    'filter:authtoken/username': value => $username_real;
    'filter:authtoken/password': value => $password_real;  
```

7. In `manifests/test_file.pp`, `$password` is defined but never used 
8. In `manifests/keymaster.pp`,  `$username` and `$password` is used in `swift_keymaster_config {}`
9. In `manifests/dispersion.pp`,  `$username` is used as a command lien argument in `"swift -A ${auth_url} --os-username ${auth_user} --os-project-name ${auth_tenant} --os-password ${auth_pass} -V ${auth_version} stat | grep 'Account: '",`
and `$password` is used in `swift_dispersion_config {}`
10. In `manifests/bench.pp`,  `$auth_url` and `$swift_user` is used in `swift_bench__config {}`
11. In `manifests/auth_file.pp`,  `$admin_password` and `$admin_user` is exported as a text file using: 
```
    content =>
  "
  export ST_USER=${admin_tenant}:${admin_user}
  export ST_KEY=${admin_password}
  export ST_AUTH=${auth_url}
  ",
```
in `file { '/root/swiftrc':} `  **VERY INTERESTING. COOL!** 

12. In `tests/site.pp` the following 

```
  class { '::swift::proxy::authtoken':
    password  => $swift_admin_password,
    # assume that the controller host is the swift api server
    auth_host => $swift_keystone_node,
  }
```

calls `class swift::proxy::authtoken(){}` with `password` in `manifests/proxy/authtoken.pp` , which is used in 
`swift_proxy_config {}` 


13. In `tests/all.pp` the following 

```
class { '::swift::proxy::tempauth':
  account_user_list => [
    {
      'user'    => 'admin',
      'account' => 'admin',
      'key'     => 'admin',
      'groups'  => [ 'admin', 'reseller_admin' ],
    },
  ]
}
```

calls `class swift::proxy::tempauth(){}` with `account_user_list` in `manifests/proxy/tempauth.pp` , which is used in 
`class swift::proxy::tempauth () {}` 

> Single script tracking handled by TaintPup. Cross script tracking needed for #13 ... TODO 


#### Repository-28

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-rally-2018-06/` 


1. In `manifests/ironic.pp` the following use of `pick()` allows introduction of security smells that are TPs. 

```
$db_user                    = pick($ironic_hash['db_user'], 'ironic')
$db_password                = pick($ironic_hash['password'], 'ironic')
```
If the first argument does not match, then second argument will be assigned. However in that script `$db_password`
and `$db_user` are never used so reporting will be FP. 

> Single script tracking handled by TaintPup. 

#### Repository-29

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-ceph-2018-06/` 

1. In `manifests/profile/params.pp` , `  $rgw_keystone_admin_user, $rgw_keystone_admin_password` is defined but not used , so FP 
2. In `manifests/repo.pp` , `source => 'https://download.ceph.com/keys/release.asc',` is a TP , `id     => '08B73419AC32B4E966C1A330E84AC2C0460F3994',` is a FP , `mirrorlist => "http://mirrors.fedoraproject.org/metalink?repo=epel-${el}&arch=\$basearch",` is a TP 

> Single script tracking handled by TaintPup. But there is also a parser limitation as observed below: 

```
invoke ensure_resource 'keystone_endpoint' (cat '' (str $region) '/swift::object-store') ({} ('ensure' 'present') ('public_url' $public_url) ('admin_url' $admin_url) ('internal_url' $internal_url))

For 

  ensure_resource('keystone_endpoint', "${region}/swift::object-store", {
    'ensure'       => 'present',
    'public_url'   => $public_url,
    'admin_url'    => $admin_url,
    'internal_url' => $internal_url,
  } )


Need even more better parsing may be another project 
```


#### Repository-30

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-cisco-aci-2018-06/` 

1. In `deployment_scripts/puppet/site.pp` , `admin_username    => $access_hash['user']` and `admin_password    => $access_hash['password'],` are FPs. 

> handled by TaintPup 

#### Repository-31

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-murano-2018-06/` 

1. In `manifests/db/postgresql.pp` , `password_hash => postgresql_password($user, $password),` is a FP.  `$privileges = 'ALL',` is privilege escalation not reported before , also a TP as used by `::openstacklib::db::postgresql {}`

2. In `manifests/db/mysql.pp` , `password_hash => mysql_password($password),` is a FP 

> TODO: protege escalation will need use of resource dict. Rest handled by TaintPup 


#### Repository-32

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-opendaylight-2018-06/` 

1. In `manifests/odl-ml2-configuration.pp` , `$auth_password      = $neutron_config['keystone']['admin_password']` is a FP 
2. In `manifests/opendaylight/service.pp` `$password` is used in `exec { 'wait-until-odl-ready':} as a command`, TP but not detected 

> Handled by TaintPup 

#### Repository-33

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-nova-2018-06/`

1. In `manifests/metadata/novajoin/` , `$password = $::os_service_default,` is a FP. 
2. In `manifests.network/neutron.pp`, `'neutron/password': value => $neutron_password, secret => true;` ensures secret is not logged in console. Absence of `secret => true` can be a new category called `secret leakage` 
3. In `manifests/cron/archived_deleted_rows.pp` , `user => pick($user, $::nova::params::nova_user),` is a TP. 
4. In `examples/nova_wsgi.pp` and `examples/nova_with_pacemaker.pp`, `admin_password => 'a_big_secret'` is passed into `manifests/api/pp` but not used, so FP 

> 2 does not map to a CWE or does not map to a smell, so will not be included in this paper. 3 is not a TP as not values are assigned to the variable . Rest handled by TaintPup 



#### Repository-34

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-cinder-2018-06/`

1. In `manifests/quota_set.pp` , `$os_password` is a TP as it is assigned as an ENVIRONMENT variable in `environment => $cinder_env,` by using 

```
$cinder_env = [
      "OS_TENANT_NAME=${os_tenant_name}",
      "OS_USERNAME=${os_username}",
      "OS_PASSWORD=${os_password}",
      "OS_AUTH_URL=${os_auth_url}",
    ]
```

> Need to track lists ... TODO. Rest. Handled by TaintPup  

#### Repository-35

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-openstack-cookiecutter-2018-06/`

1. Nothing found or already detected 


> Handled by TaintPup

#### Repository-36

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-lma-infrastructure-alerting-2018-06/`

1. In `deployment_scripts/modules/lma_infra_alerting/manifests/nagios/check_http.pp`, `$password` was used in `$auth_basic_option`
, which is in turn used in `$command_line`, and then in `nagios::command {}` as `command_line => $command_line`

> Puppet parser can't parse the following ... fails to handle variables under define 

```
define lma_infra_alerting::nagios::check_http(
  $host_name = undef,
  $contact_group = $lma_infra_alerting::params::nagios_contactgroup,
  $service_description = undef,
  $custom_address = undef,
  $port = undef,
  $url = '/',
  $username = undef,
  $password = undef,
  $string_expected_in_status = '200 OK',
  $string_expected_in_content = undef,
  $string_expected_in_headers = undef,
  $response_time_warning = 2,
  $response_time_critical = 3,
  $timeout = 5,
){
```

> Rest handled by TaintPup

#### Repository-37

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-nsx-t-2018-06/`

1. Nothing found or previously addressed 

> Handled by TaintPup



#### Repository-38

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-gnocchi-2018-06/`

1. In `examples/site.pp` `class { '::gnocchi::keystone::auth':}` has `password`, which is passed into `manifests/keystone/auth.pp` as
` keystone::resource::service_identity {}` 

> Need to do cross script tracking. TODO. Rest handled by TaintPup 

#### Repository-39

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-onos-2018-06/`

1. In `deployment_scripts/puppet/manifests/onos-dashboard.pp`, `$password` used in  `$dashboard_desc`, which is used in 
`$json_hash`, that is used in `$json_message` and then in `command => "/usr/bin/curl -H 'Content-Type: application/json' -X POST \
-d '${json_message}' \` 

> Handled by TaintPup 

#### Repository-40 

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-lma-collector-2018-06/`

1. In `deployment_scripts/puppet/manifests/onos-dashboard.pp`,

Side point: not all strings are escaped as below: 
```
  $config = {
    'Username' => "\"${username}\"",
    'Password' => "\"${password}\"",
  }
```

2. In `deployment_scripts/puppet/modules/heka/manifests/dashboard.pp`, is `$$dashboard_address` declared but not used. 

3. In `manifests/hiera_override.pp`, `$mysql_password = $nova['db_password']` is not a hard-coded password, so FP 

4. In `manifests/controller.pp` `password                  => hiera('lma::collector::infrastructure_alerting::password'),` is not a hard-coded password, so FP 

> Handled by TaintPup 

#### Repository-41

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-midonet-2018-06/`

1. Nothing found or reported previously 

> Handled by TaintPup 


#### Repository-42

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-bigswitch-2018-06/`

1. Nothing found or reported previously 

> Handled by TaintPup 



#### Repository-43

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-qdr-2018-06/`

1. Nothing found or reported previously 

> Handled by TaintPup 


#### Repository-44

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-trove-2018-06/`

1. In `examples/site.pp`, `class { '::trove::db::mysql':}` uses `password`, that is passed into `class trove::db::mysql(){}`
in `manifests/db/mysql.pp` 

2. In `examples/site.pp`, `class { '::trove::keystone::auth':}` uses ` password`, that is passed into `class trove::keystone::auth (){}` in `keystone/auth.pp`

> Need to do cross script tracking. TODO. 

#### Repository-45

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-datera-cinder-2018-06/`

1. Nothing found or previously reported 

> Handled by TaintPup 

#### Repository-46

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-manila-2018-06/`

1. Nothing found or previously reported 

> Handled by TaintPup 


#### Repository-47

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-influxdb-grafana-2018-06/`

1. Nothing found or previously reported 

> Handled by TaintPup 

#### Repository-48

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-mistral-2018-06/`

1. Nothing found or previously reported 

> Handled by TaintPup 

#### Repository-49

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-zaqar-2018-06/`

1. Nothing found or previously reported 

> Handled by TaintPup 

#### Repository-50

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-elasticsearch-kibana-2018-06/`

1. Nothing found or previously reported 

> Handled by TaintPup 

#### Repository-50

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-magnum-2018-06/`

1. In `examples/magnum.pp`, password is passed as `class { '::magnum::db::mysql':` in `class magnum::db::mysql(){}` located at `manifests/db/mysql.pp`. Similarly,  `domain_password => 'oh_my_no_secret',` is used in `class { '::magnum::keystone::domain': }`
that calls `class magnum::keystone::domain () {}` in `manifests/keystone/domain.pp`. Eventually the password is used in `magnum_config {}` 

> Need to do cross script tracking. TODO. Rest handled by TaintPup 


#### Repository-51

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-oslo-2018-06/`

1. Nothing found or identified previously 

> Handled by TaintPup 

#### Repository-52

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-sahara-2018-06/`

1. In `examples/basic.pp` , `host => '0.0.0.0',` is passed into `manifests/init.pp` through `class sahara(){}`, which is eventually used in `sahara_config {}`

> Need to do cross script tracking. TODO. Rest handled by TaintPup 


#### Repository-53

Location:  `/Users/Brahmin/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-6wind-virtual-accelerator-2018-06/`

1. Nothing found or identified previously 


> Handled by TaintPup 

#### Repository-54

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-midonet-2018-06/`

1. In `manifests/repo/centos.pp`, `$mem_password` and `$mem_username` are used in `$midonet_core_repo_url      = "http://${mem_username}:${mem_password}@${midonet::params::midonet_repo_baseurl}/mem-${mem_version}/${midonet_stage}/el${::operatingsystemmajrelease}"` , which is later used in `yumrepo {}`


> Handled by TaintPup 

#### Repository-55

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/packstack-2018-06/`

1. In `manifests/nova/api.pp`, passwords that use hiera are not hard-coded, so should be excluded `$admin_password = hiera('CONFIG_NOVA_KS_PW')` is later used in `class {'::nova::keystone::authtoken':}`

2. In `manifests/keystone/gnochhi.pp` `internal_url => "http://${gnocchi_keystone_host_url}:8041",` is a TP, as `HTTP` is directly 
used and assigned to an attribute.  

> Handled by TaintPup 

> TEST_CASE: Use this repo to test one-level and multi-level taint tracking 

#### Repository-56

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-glance-2018-06/`

1. Nothing found or already reported 

> Handled by TaintPup 

#### Repository-57

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-keystone-2018-06/`

1. In `examples/v3_basic.pp`, `admin_token         => 'admin_token',` in `class { '::keystone': }` calls `class keystone() {}`
in `keystone_config {}` inside `manifests/init.pp` 

2. In `examples/v3_basic.pp`, `public_url => 'http://127.0.0.1:5000/',` in `class keystone::endpoint (){}` calls `class keystone() {}`
in `keystone::resource::service_identity {}` inside `manifests/endpoint.pp` 

3. In `examples/v3_basic.pp`, `password => 'a_big_secret',',` in `class { '::keystone::roles::admin':}` calls `class keystone::roles::admin(){}` in `keystone_user {}` inside `roles/admin.pp` 

> Need to do cross script tracking. Rest handled by TaintPup 

#### Repository-58

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-library-2018-06/`



1. In `deplyoment/puppet/fuel/cluster/manifests/mysql.pp`, `$password',` used in `$init_file_contents`, which is later used in  `command => "echo \"${init_file_contents}\" > /tmp/wsrep-init-file",` inside `exec { 'create-init-file': }` 

2. In `deplyoment/puppet/fuel/manifests/ostf/auth.pp`, `$password         = $::fuel::params::keystone_ostf_password,` is a FP 

3. In `deplyoment/puppet/fuel/manifests/puppetsync.pp`, `$bind_address  = '0.0.0.0',` is assigned but not assigned, so FP. 

4. `$admin_password            = dig44($neutron_config, ['keystone', 'admin_password'])` is a FP in `deplyoment/puppet/fuel/manifests/openstack_tasks/manifests/openstack_network/server_config.pp`

5. `$rabbit_password      = $murano_hash['rabbit_password']` not a hard-coded password and used in `command => "rabbitmqctl -n '${rabbit_node_name}' add_user '${rabbit_user}' '${rabbit_password}'",` for `exec { 'create_murano_user' :`


> Handled by TaintPup 

> Parser limitation ... cannot detect attributes that are of the following format: 

```
  $default_ceilometer_hash = {
    'enabled'                    => false,
    'db_password'                => 'ceilometer',
    'user_password'              => 'ceilometer',
    'metering_secret'            => 'ceilometer',
    'http_timeout'               => '600',
    'event_time_to_live'         => '604800',
    'metering_time_to_live'      => '604800',
  }
```


#### Repository-59

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-designate-2018-06/`

1. Nothing found or previously reported 


> Handled by TaintPup 

#### Repository-60

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-external-zabbix-2018-06/`

1. In `deployment_scripts/modules/plugin_zabbix/manifests/db/mysql.pp`, `$db_passwd = $mysql_db['root_password']` is used in `$mysql_extras_args` that is later used in `command     => "/usr/bin/mysql ${mysql_extras_args} ${plugin_zabbix::params::db_name} < /tmp/zabbix/schema.sql",`, inside `exec { "${plugin_zabbix::params::db_name}-import":}` 


> Handled by TaintPup 

#### Repository-61

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-murano-2018-06/`

1. Nothing found or already reported 

> Handled by TaintPup 


#### Repository-62

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-ironic-2018-06/`

1. In `examples/ironic.pp`, `class { '::ironic::bifrost': }`, passes hard-coded passwords into `class ironic::bifrost (){}` that is located in `manifests/bifrost.pp` . The two passwords `  $ironic_db_password and $mysql_password,` are declared but not used, so FP. 


> Need to do cross script tracking. Rest handled by TaintPup 

#### Repository-63

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-barbican-2018-06/`

1. Nothing found or previously reported 

> Handled by TaintPup 

#### Repository-64

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-openstack-integration-2018-06/`

1. Nothing found or previously reported 

> Handled by TaintPup 

> Found a cool example in /Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-openstack-integration-2018-06/manifests/ceph.pp: 

```
SECRETS:::VAR_DETECTED_DICT:{"secret'": ("'AQD7kyJQQGoOBhAAqrPAqSopSwPrrfMMomzVdw'", 'API_KEY'), '$password': ("'secret'", 'PASSWORD')} 
 TAINTED_DICT:{"secret'": [('client_keys', "({} ('client.admin' ({} ('secret' 'AQD7kyJQQGoOBhAAqrPAqSopSwPrrfMMomzVdw==') ('mode' '0600') ('cap_mon' 'allow *') ('cap_osd' 'allow *') ('cap_mds' 'allow *'))) ('client.bootstrap-osd' ({} ('secret' 'AQD7kyJQQGoOBhAAqrPAqSopSwPrrfMMomzVdw==') ('keyring_path' '/var/lib/ceph/bootstrap-osd/ceph.keyring') ('cap_mon' 'allow profile bootstrap-osd'))) ('client.openstack' ({} ('secret' 'AQD7kyJQQGoOBhAAqrPAqSopSwPrrfMMomzVdw==') ('mode' '0644') ('cap_mon' 'profile rbd') ('cap_osd' 'profile rbd pool=cinder, profile rbd pool=nova, profile rbd pool=glance, profile rbd pool=gnocchi'))))", 'HARD_CODED_SECRET'), ('osds', "({} ('/var/lib/ceph/data' ({})))", 'HARD_CODED_SECRET')], '$password': [('rgw_keystone_admin_password', '$password', 'HARD_CODED_SECRET'), ('password', '$password', 'HARD_CODED_SECRET')]} 
 SECRETS:::ATTR_DETECTED_DICT:{'mon_key': ("'AQD7kyJQQGoOBhAAqrPAqSopSwPrrfMMomzVdw=='", 'API_KEY'), 'mgr_key': ("'AQD7kyJQQGoOBhAAqrPAqSopSwPrrfMMomzVdw=='", 'API_KEY'), 'rgw_user': ("'ceph'", 'USERNAME'), 'user': ("'ceph'", 'USERNAME'), 'secret': ("'AQD7kyJQQGoOBhAAqrPAqSopSwPrrfMMomzVdw=='", 'API_KEY')}

```

#### Repository-65

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-ci-2018-06/`

1. Nothing found or previously reported 

> Handled by TaintPup 

#### Repository-66

Location:  `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-tripleo-2018-06/`

1. In `manifests/profile/base/designate/api.pp`, `$listen_ip      = '0.0.0.0',` is used in `$listen_uri = normalize_ip_for_uri($listen_ip)` and then in `class { '::designate::api': }` as `listen => "${listen_uri}:${listen_port}",`


> Need to do cross script tracking. TODO. Rest handled by TaintPup 

#### Repository-67

Location: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-ceilometer-2018-06`

1. In `examples/site.pp`, the following 
```
  class { '::ceilometer::agent::auth':
    auth_url      => 'http://localhost:5000/v2.0',
    auth_password => 'tralalerotralala'
  }
```

calls `ceilometer_config {}` inside `manifests/agent/auth.pp` . This is a TP 

> Need to do cross script tracking. TODO. Rest handled by TaintPup 

#### Repository-68

Location: `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-contrail-2018-06`

1. Nothing found or previously reported 

> Handled by TaintPup 

### Other notes 

##### Parser cannot handle resources that are decalred within a else block like 

```
    } else {
        monitoring::service { 'memcached':
            description   => 'Memcached',
            check_command => "check_tcp!${port}",
        }
```

in /Users/arahman/PRIOR_NCSU/SECU_REPOS/wiki-pupp/puppet-2018-06/modules/memcached/manifests/init.pp 

##### Some scripts have syntax errors 

like `/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-onos-2018-06/deployment_scripts/puppet/manifests/neutron-start.pp` for which Puppet's parser throws 

> Error: Syntax error at '[' at line 17:24


##### Great example of showing how not all variables are used in attributes 

1. /Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-monasca-2018-06/manifests/vertica/config.pp 

`monitor_user` is assigned a value but not used in an attribute 

2.   /Users/arahman/TAINTPUP_REPOS/WIKIMEDIA/vagrant/puppet/modules/changeprop/manifests/init.pp 

```
  $restbase_uri = "http://localhost:${restbase_port}"

    service::node { 'changeprop':
        port       => $port,
        module     => 'hyperswitch',
        log_level  => $log_level,
        git_remote => 'https://github.com/wikimedia/change-propagation.git',
        config     => template('changeprop/config.yaml.erb'),
    }
```

##### Great example of TaintPup can capture data flow WAY BETTER than SLIC 
File name: /Users/arahman/TAINTPUP_REPOS/MOZILLA/puppet/modules/python/manifests/system_pip_conf.pp
```
        file {
            "${filename}":
                content => template("python/user-pip-conf.erb"),
                owner   => $user,
                group   => $group,
                mode    => "0644";
        }
```

File name: /Users/arahman/TAINTPUP_REPOS/OPENSTACK/fuel-library-2018-06/deployment/puppet/osnailyfacter/manifests/openstack/manage_cinder_types.pp

```
define osnailyfacter::openstack::manage_cinder_types (
  $ensure               = 'present',
  $volume_backend_names = {},
  $key                  = 'volume_backend_name',
) {
  if $ensure == 'present' {
    $value = $volume_backend_names[$name]
    cinder_type { $name:
      properties => ["${key}=${value}"]
    }
  } else {
    cinder_type { $name:
      ensure => absent
    }
  }
}

```
File name: /Users/arahman/TAINTPUP_REPOS/GITHUB/cisco@cisco-network-puppet-module/examples/cisco/demo_ospf.pp 
```
 $auth_password = '3109a60f51374a0d'
  cisco_ospf_area_vlink { 'dark_blue vrf2 12345 1.1.1.1':
    ensure                             => 'present',
    auth_key_chain                     => 'myKeyChain',
    authentication                     => md5,
    authentication_key_encryption_type => '3des',
    authentication_key_password        => $auth_password,
    dead_interval                      => 500,
    hello_interval                     => 2000,
    message_digest_algorithm_type      => md5,
    message_digest_encryption_type     => cisco_type_7,
    message_digest_key_id              => 39,
    message_digest_password            => $md_password,
    retransmit_interval                => 10000,
    transmit_delay                     => 400,
  }

```
##### Nested switch cases statements are problematic 

/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-library-2018-06/deployment/puppet/fuel/manifests/astute.pp

/Users/arahman/PRIOR_NCSU/SECU_REPOS/mozi-pupp/puppet-2018-06/modules/talos/manifests/init.pp 

