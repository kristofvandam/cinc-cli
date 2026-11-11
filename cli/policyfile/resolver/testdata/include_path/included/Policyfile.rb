name 'base'
run_list 'base::default'
named_run_list :setup, 'util::default'
cookbook 'base', path: '../cookbooks/base'
cookbook 'util', path: '../cookbooks/util'
default['base']['tz'] = 'UTC'
default['shared'] = 'same'
override['base']['hardening'] = true
