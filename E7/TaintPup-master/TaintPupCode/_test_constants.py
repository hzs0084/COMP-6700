'''
Akond Rahman 
Dec 13, 2020 
Constants needed to do testing 
'''

common_error_string = 'DOES NOT MATCH:::Should be '

_multi_taint_script_name    = 'TestArtifacts/onos-dashboard.pp' 
_multi_taint_var_input      = '$password'
_multi_taint_var_output     = '$json_message'
_multi_taint_var_error_msg  = common_error_string + _multi_taint_var_output 

_liveness_script_name    = 'TestArtifacts/packstack.keystone.gnocchi.pp'
_liveness_var_input_list = [  '$auth_name', '$password', '$public_url', '$admin_url', '$internal_url', '$public_url_s3', '$admin_url_s3', '$internal_url_s3' ]
_liveness_error_msg      = common_error_string + 'TRUE' 

_single_taint_script_name = 'TestArtifacts/puppet-ec2api.db.postgresql.pp' 
_single_taint_var         = 'user' 
_single_taint_dict_key    = 'user' 
_single_taint_type        = 'USERNAME' 
_single_taint_error_true  = common_error_string + 'TRUE' 
_single_taint_error_msg   = common_error_string + 'user' 
OUTPUT_SECRET_KW          = 'HARD_CODED_SECRET'

_susp_script_1  = 'TestArtifacts/wiki.planet.pp'
_susp_script_2  = 'TestArtifacts/wiki.realm.pp' 
_susp_error_msg = common_error_string + '5'


_missing_default_script_name = 'TestArtifacts/test.api.v2.pp' 
_missing_default_script2     = 'TestArtifacts/locales.all.pp'
_missing_default_script3     = 'TestArtifacts/tripleo.base.pacemaker.pp'
_missing_default_script4     = 'TestArtifacts/fuel-library.cinder.pp'
_missing_default_script5     = 'TestArtifacts/openstack_cinder.pp'
_missing_default_script6     = 'TestArtifacts/pacemaker.mysql_bundle.pp'
_missing_default_script7     = 'TestArtifacts/tripleo.haproxy.pp'
_missing_default_script8     = 'TestArtifacts/ceilometer.controller.pp'
_missing_default_script9     = 'TestArtifacts/puppet.tripleo.gnocchi.api.pp'
_missing_default_script10    = 'TestArtifacts/puppet.tripleo.glance.api.pp'
_missing_default_script11    = 'TestArtifacts/gitlab.simp.repo.pp'
_missing_default_msg         = common_error_string + '1'
_present_default_script_name = 'TestArtifacts/sample.params.switch.case.pp'
_present_default_msg         = common_error_string + '0'

_invalid_ip_script_name1 = 'TestArtifacts/sample.init1.pp' 
_invalid_ip_script_name2 = 'TestArtifacts/sample.init2.pp' 
_invalid_ip_script_name3 = 'TestArtifacts/ostk.packstack.magnum.pp'
_invalid_ip_msg1         = common_error_string + '1'
_invalid_ip_msg0         = common_error_string + '0'

_http_var_script_name    = 'TestArtifacts/sample.auth.pp' 
_http_msg_1              = common_error_string + '1'
_http_msg_0              = common_error_string + '0'
_http_attr_script_name   = 'TestArtifacts/sample.onos.dashboard.pp'

_weak_cryp_script_name    = 'TestArtifacts/test.api.pp' 
_weak_cryp_msg_           = common_error_string + '3'


_empty_pass_script_name    = 'TestArtifacts/oozie.pp' 
_tainted_empty_pass_script = 'TestArtifacts/ostk.ci.fuel.project.zabbix.server.pp'
_tainted_pass_script       = 'TestArtifacts/sensu.postgresql.pp'
_empty_pass_msg_           = common_error_string + '1'

_default_adm_script_name   = 'TestArtifacts/test.api.pp' 
_default_adm_msg_          = common_error_string + '1'

_secret_script_name   = 'TestArtifacts/sample.onos.dashboard.pp' 
_secret_script_v2     = 'TestArtifacts/mozi.signing.server.pp'
_secret_script_v3     = 'TestArtifacts/relabs.signing.server.pp'
_secret_script_v4     = 'TestArtifacts/mozi.redhat.uname.pp'
_secret_script_v5     = 'TestArtifacts/ostk.ldap.backend.pp'
_secret_script_v6     = 'TestArtifacts/ostk.integration.nova.pp'
_secret_script_v7     = 'TestArtifacts/ostk.cloud.controller.pp'
_secret_msg_          = common_error_string + '2'
_secret_uname         = 'karaf'
_secret_password      = 'karaf'
_secret_flag_status   = 'TRUE'
_secret_strange_config_script ='/Users/arahman/TAINTPUP_REPOS/GITHUB/derekhiggins@packstack/packstack/puppet/templates/cinder.pp'


_username_script_name   = 'TestArtifacts/oozie.database.mysql.pp' 

_taintedHttp_script_v1 = 'TestArtifacts/packstack.keystone.magnum.pp'
_tainted_http_msg_v1   = common_error_string + '3'
_taintedHttp_script_v2 = 'TestArtifacts/packstack.keystone.manila.pp'
_tainted_http_msg_v2   = common_error_string + '5'
_taintedHttp_script_v3 = 'TestArtifacts/packstack.keystone.cinder.pp'
_tainted_http_msg_v3   = common_error_string + '9'
_taintedHttp_script_v4 = 'TestArtifacts/http.scheme.gse.nagios.pp'
_tainted_http_msg_v4   = common_error_string + '1'
_taintedHttp_script_v5 = 'TestArtifacts/http.scheme.afd.nagios.pp'
_tainted_http_msg_v5   = common_error_string + '1'

OUTPUT_HTTP_KW         = 'INSECURE_HTTP'

_cross_taint_script_1  = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-trove-2018-06/examples/site.pp'
_cross_taint_msg_1     =  common_error_string + '7'
_cross_taint_script_2  = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-magnum-2018-06/examples/magnum.pp' 
_cross_taint_script_3  = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-keystone-2018-06/examples/v3_basic.pp'
_cross_taint_script_4  = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-ironic-2018-06/examples/ironic.pp'
_cross_taint_script_5  = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-ceilometer-2018-06/examples/site.pp'
_cross_taint_script_6  = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-neutron-2018-06/examples/neutron.pp'
_cross_taint_script_7  = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-vitrage-2018-06/examples/vitrage.pp'
_cross_taint_script_8  = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-gnocchi-2018-06/examples/site.pp'

_cross_taint_script_ip = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-sahara-2018-06/examples/basic.pp' 
_cross_taint_script_http = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-pupp/puppet-ceilometer-2018-06/examples/site.pp'

_weak_crypt_script       = 'TestArtifacts/test.pp' 


_empirical_script_ip     = 'TestArtifacts/wiki.memcached.init.pp'
_empirical_script_http   = 'TestArtifacts/wiki.vagrant.raita.pp' 
_empirical_script_secret = 'TestArtifacts/wiki.aptrepo.init.pp'
_empirical_script_empty  = 'TestArtifacts/tarnslatewiki.init.pp'
_empirical_script_d_adm  = 'TestArtifacts/wiki.superset.init.pp'
_empirical_script_md5    = 'TestArtifacts/wiki.postgresql.user.pp'


_empirical_hop_http      = 'TestArtifacts/wiki.apt.init.pp'

_aggregate_script_ip     = 'TestArtifacts/ostk.barbican.api.pp'
_aggregate_script_http   = 'TestArtifacts/ostk.ceph.http.repo.pp'

_integration_structure   = 'TestArtifacts/hiera.pp'
_integration_default     = 'TestArtifacts/cinder.pp'

_example_domain_str      = 'http://internal.example.com:8080/twelfth'
