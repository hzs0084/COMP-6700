[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) 

[![forthebadge made-with-python](http://ForTheBadge.com/images/badges/made-with-python.svg)](https://www.python.org/)

[![Actions Status](https://github.com/paser-group/TaintPup/workflows/Build%20TaintPupp/badge.svg)](https://github.com/Build%20TaintPupp/actions)


# TaintPup: Taint Tracking to Facilitate Better Secuirty Analysis for Puppet 

## Main developer

Akond Rahman 

## Colloborator 

Chris Parnin 

### Details 

Building a taint tracking tool that follows the flow of security weaknesses, such as hard-coded passwords and use of weak crpotgraphy 
algorithms. 

Abstract: 

Despite being beneficial for managing computing infrastructure automatically, Puppet manifests are susceptible to security weaknesses, e.g., 
hard-coded secrets and use of weak cryptography algorithms. Adequate mitigation of security weaknesses in Puppet manifests is thus necessary to 
secure computing infrastructure that are managed with Puppet manifests. A characterization of how security weaknesses propagate and affect 
Puppet-based infrastructure management, can inform practitioners on the relevance of the detected security weaknesses, as well as help them 
take necessary actions for mitigation. We conduct an empirical study with 17,629 Puppet manifests with Taint Tracker for Puppet Manifests 
(TaintPup). We observe 2.4 times more precision, and 1.8 times more F-measure for TaintPup, compared to that of a state-of-the-art security 
static analysis tool. From our empirical study, we observe security weaknesses to propagate into 4,457 resources, i.e, Puppet-specific code 
elements used to manage infrastructure. A single instance of a security weakness can propagate into as many as 35 distinct resources. We 
observe security weaknesses to propagate into 7 categories of resources, which include resources used to manage continuous integration servers 
and network controllers. According to our survey with 24 practitioners, propagation of security weaknesses into data storage-related resources 
is rated to have the most severe impact for Puppet-based infrastructure management.


Pre-print: https://arxiv.org/pdf/2208.01242.pdf 

Source code: https://github.com/paser-group/TaintPup 

Test cases: https://github.com/paser-group/TaintPup/blob/514ae5ad3f79f12770bb580fac65c3d289bb4357/.github/workflows/python-app.yml#L37 

 
