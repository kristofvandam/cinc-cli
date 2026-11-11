name 'float_attrs'
run_list 'base'
cookbook 'base', path: 'cookbooks/base'
default['sum'] = 0.1 + 0.2
default['whole'] = 1.0
default['big'] = 1.0e20
default['small'] = 1.0e-5
default['ratio'] = 0.75
