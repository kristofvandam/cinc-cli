name 'include_path'
include_policy 'base', path: 'included/Policyfile.lock.json'
run_list 'app::default', 'base::default'
cookbook 'app', path: 'cookbooks/app'
default['app']['port'] = 8080
default['shared'] = 'same'
