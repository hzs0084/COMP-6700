### Track Progress of Cross Script Taint Tracking 

#### Following Examples Need to be Handled 

###### Example-1 

Location: /Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-trove-2018-06/

In examples/site.pp, class { '::trove::db::mysql':} uses password, that is passed into class trove::db::mysql(){} in manifests/db/mysql.pp

In examples/site.pp, class { '::trove::keystone::auth':} uses password, that is passed into class trove::keystone::auth (){} in keystone/auth.pp


> Found a parser limitation .... cannot detect variables like $password in 

```
class trove::keystone::auth (
  $password,
} 
```

> Handled by TaintPup 

###### Example-2 

Location: /Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-magnum-2018-06/

In examples/magnum.pp, password is passed as class { '::magnum::db::mysql': in class magnum::db::mysql(){} located at manifests/db/mysql.pp. Similarly, domain_password => 'oh_my_no_secret', is used in class { '::magnum::keystone::domain': } that calls class magnum::keystone::domain () {} in manifests/keystone/domain.pp. Eventually the password is used in magnum_config {} 

> Handled by TaintPup 


###### Example-3 

Location: /Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-sahara-2018-06/

In examples/basic.pp , host => '0.0.0.0', is passed into manifests/init.pp through class sahara(){}, which is eventually used in sahara_config {} 

> handled by TaintPup 

###### Example-4 

Location: /Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-keystone-2018-06/

In examples/v3_basic.pp, admin_token => 'admin_token', in class { '::keystone': } calls class keystone() {} in keystone_config {} inside manifests/init.pp

In examples/v3_basic.pp, public_url => 'http://127.0.0.1:5000/', in class keystone::endpoint (){} calls class keystone() {} in keystone::resource::service_identity {} inside manifests/endpoint.pp

In examples/v3_basic.pp, password => 'a_big_secret',', in class { '::keystone::roles::admin':} calls class keystone::roles::admin(){} in keystone_user {} inside roles/admin.pp

> Handled by TaintPup 

###### Example-5 

Location: /Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-ironic-2018-06/

In examples/ironic.pp, class { '::ironic::bifrost': }, passes hard-coded passwords into class ironic::bifrost (){} that is located in manifests/bifrost.pp . The two passwords $ironic_db_password and $mysql_password, are declared but not used, so FP.

> Handled by TaintPup 

###### Example-6 

Location: /Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-tripleo-2018-06/

In manifests/profile/base/designate/api.pp, $listen_ip = '0.0.0.0', is used in $listen_uri = normalize_ip_for_uri($listen_ip) and then in class { '::designate::api': } as listen => "${listen_uri}:${listen_port}",

> handled by TaintPup 

###### Example-7 

Location: /Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-ceilometer-2018-06

In examples/site.pp, the following
```
  class { '::ceilometer::agent::auth':
    auth_url      => 'http://localhost:5000/v2.0',
    auth_password => 'tralalerotralala'
  }
``` 
calls ceilometer_config {} inside manifests/agent/auth.pp . This is a TP  

> Handled by TaintPup 

###### Example-8 

Location:/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/fuel-plugin-plumgrid-2018-06/deployment_scripts/puppet/modules/plumgrid/manifests/init.pp

class plumgrid is a class that inherits plumgrid::params means a class needs sth. that comes from params.pp which is plumgrid/manifests/

> Not sure what to make of it as it does not help in security smell identification ... so skipping 

###### Example-9 

Location: /Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-neutron-2018-06

examples/neutron.pp: password => 'secrete', in class { '::neutron::server::notifications': calls manifests/server/notifications.pp with password that flows into neutron_config {}

examples/cisco_ml2.pp:

class {'::neutron::plugins::ml2::cisco::ucsm':
  ucsm_username  => 'admin',
  ucsm_password  => 'password',
}  
calls manifests/plugins/ml2/cisco/uscm.pp with ucsm_username and ucsm_password that flows into neutron_plugin_ml2 {}

In manifests/plugins/ml2/cisco/uscm.pp
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
username and password flows within $nexus_config, into class neutron::plugins::ml2::cisco::nexus(){} in manifests/plugins/ml2/cisco/nexus.pp

> Handled by TaintPup 

###### Example-10

Location:/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-vitrage-2018-06/ 

In examples/vitrage.pp, class { '::vitrage::keystone::auth':} calls manifests/keystone/auth.pp with
```
  admin_url    => 'http://127.0.0.1:8999',
  internal_url => 'http://127.0.0.1:8999',
  public_url   => 'http://127.0.0.1:8999',
  password     => 'a_big_secret',
```

which is propagated into keystone::resource::service_identity {} in manifests/keystone/auth.pp

In examples/vitrage.pp, class { '::vitrage::api':} calls manifests/api.pp, but the specifed paramers mentioned below go nowhere
```
  keystone_password     => 'a_big_secret',
  keystone_identity_uri => 'http://127.0.0.1:35357/',
```

In examples/vitrage.pp, class { '::vitrage::auth':} calls manifests/auth.pp, with parameters below
```
  auth_password => 'a_big_secret',
``` 
that is propagated into vitrage_config {} in manifests/auth.pp

> Handled by TaintPup 

###### Example-11

Location: /Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-rally-2018-06/

In example/rally.pp, class { '::rally::settings': } calls manifests/settings.pp and class { '::rally': }

> Handled by TaintPup 

###### Example-12

Location: /Users/arahman/PRIOR_NCSU/SECU_REPOS/puppet-swift-2018-06/

In tests/site.pp the following
```
  class { '::swift::proxy::authtoken':
    password  => $swift_admin_password,
    # assume that the controller host is the swift api server
    auth_host => $swift_keystone_node,
  }
```
calls class swift::proxy::authtoken(){} with password in manifests/proxy/authtoken.pp , which is used in swift_proxy_config {}

In tests/all.pp the following
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
calls class swift::proxy::tempauth(){} with account_user_list in manifests/proxy/tempauth.pp , which is used in class swift::proxy::tempauth () {}

> Handled by TaintPup ... attributes in  list are not handled yet 

###### Example-13 

Location: /Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-gnocchi-2018-06/

In examples/site.pp class { '::gnocchi::keystone::auth':} has password, which is passed into manifests/keystone/auth.pp as keystone::resource::service_identity {}

> Handled by TaintPup  