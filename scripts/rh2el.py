#!/usr/bin/env python2
# -*- coding:utf8 -*-

'''
Descripts: Convert Red Hat OVAL to Enterprise Linux
Author: Sep0lkit
Version: 1.1
Update: 2019/07/05
Website: https://github.com/Sep0lkit/oval-for-el
'''

import os
import sys
import argparse
import xml.etree.ElementTree as ET


'''
    NAMESPACES
'''
ET.register_namespace('', "http://oval.mitre.org/XMLSchema/oval-definitions-5")
ET.register_namespace('oval', "http://oval.mitre.org/XMLSchema/oval-common-5")
ET.register_namespace('red-def', "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux")


OVAL_NS = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
OVAL_RED_NS = "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"

'''
    Global Variables
'''
PLATFORMS_RH_EL = {'Red Hat Enterprise Linux 8':'Community Enterprise Operating System 8','Red Hat Enterprise Linux 7':'Community Enterprise Operating System 7','Red Hat Enterprise Linux 6':'Community Enterprise Operating System 6','Red Hat Enterprise Linux 5':'Community Enterprise Operating System 5'}


CPES_RH_EL = {'cpe:/o:redhat:enterprise_linux:8':'cpe:/o:centos:centos:8','cpe:/o:redhat:enterprise_linux:7':'cpe:/o:centos:centos:7','cpe:/o:redhat:enterprise_linux:6':'cpe:/o:centos:centos:6','cpe:/o:redhat:enterprise_linux:5':'cpe:/o:centos:centos:5'}


''' 
    定义自定义规则: CentOS
'''

RULE_VERSION = '101'

DEFINS_OF_EL5 = {'tst_comment':'centos-release 5 is installed', 'tst_id':'oval:com.github.sep0lkit:tst:190630001', 'obj_id':'oval:com.github.sep0lkit:obj:190630001', 'ste_id':'oval:com.github.sep0lkit:ste:190630001', 'obj_name':'centos-release', 'ste_version':'^5' }

DEFINS_OF_EL6 = {'tst_comment':'centos-release 6 is installed', 'tst_id':'oval:com.github.sep0lkit:tst:190630002', 'obj_id':'oval:com.github.sep0lkit:obj:190630002', 'ste_id':'oval:com.github.sep0lkit:ste:190630002', 'obj_name':'centos-release', 'ste_version':'^6' }

DEFINS_OF_EL7 = {'tst_comment':'centos-release 7 is installed', 'tst_id':'oval:com.github.sep0lkit:tst:190630003', 'obj_id':'oval:com.github.sep0lkit:obj:190630003', 'ste_id':'oval:com.github.sep0lkit:ste:190630003', 'obj_name':'centos-release', 'ste_version':'^7' }

DEFINS_OF_EL8 = {'tst_comment':'centos-release 8 is installed', 'tst_id':'oval:com.github.sep0lkit:tst:190630004', 'obj_id':'oval:com.github.sep0lkit:obj:190630004', 'ste_id':'oval:com.github.sep0lkit:ste:190630004', 'obj_name':'centos-release', 'ste_version':'^8' }


''' tst id for redhat os definitions '''
redhat_8_tests = ['oval:com.redhat.rhsa:tst:20190966005', 'oval:com.redhat.rhsa:tst:20191619022']

'''redhat_7_tests = ['oval:com.redhat.rhba:tst:20150364001','oval:com.redhat.rhba:tst:20150364002','oval:com.redhat.rhba:tst:20150364003','oval:com.redhat.rhba:tst:20150364004','oval:com.redhat.rhsa:tst:20140741010','oval:com.redhat.rhsa:tst:20140741011','oval:com.redhat.rhsa:tst:20140741012','oval:com.redhat.rhsa:tst:20140741013']'''

redhat_7_tests = ['oval:com.redhat.rhba:tst:20150364027', 'oval:com.redhat.rhba:tst:20150364028', 'oval:com.redhat.rhba:tst:20150364029', 'oval:com.redhat.rhba:tst:20150364030', 'oval:com.redhat.rhsa:tst:20140741015', 'oval:com.redhat.rhsa:tst:20140741016', 'oval:com.redhat.rhsa:tst:20140741017', 'oval:com.redhat.rhsa:tst:20140741018']

redhat_6_tests = ['oval:com.redhat.rhsa:tst:20140741006', 'oval:com.redhat.rhsa:tst:20140741007', 'oval:com.redhat.rhsa:tst:20140741008', 'oval:com.redhat.rhsa:tst:20140741009', 'oval:com.redhat.rhba:tst:20111656003', 'oval:com.redhat.rhba:tst:20111656004', 'oval:com.redhat.rhba:tst:20111656005', 'oval:com.redhat.rhba:tst:20111656006', 'oval:com.redhat.rhsa:tst:20100889007', 'oval:com.redhat.rhsa:tst:20100889008', 'oval:com.redhat.rhsa:tst:20100889009', 'oval:com.redhat.rhsa:tst:20100889010']

redhat_5_tests = ['oval:com.redhat.rhsa:tst:20140741003', 'oval:com.redhat.rhsa:tst:20100889026', 'oval:com.redhat.rhba:tst:20070331005']


'''
    Functions
'''
def parse_args():
    parser = argparse.ArgumentParser(description="redhat oval definition adapt to centos")
    parser.add_argument("oval_file", help="redhat oval file path")
    parser.add_argument("output_file", help="redhat oval output file path")
    return parser.parse_args()

def parse_xml(file_name):
    ''' 
    Given a filename, return the root of the ElementTree
    ''' 
    try:
        it = ET.parse(file_name)
        return it
    except:
        sys.stderror.write("Error while  loadding file " + file_name + ".\n")
        exit(-1)
        
# in-place prettyprint formatter
def indent(elem, level=0):
    i = "\n" + level*"  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
        for elem in elem:
            indent(elem, level+1)
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = i

def alter_affected_platforms(definition):
    affected = definition.find(".//{%s}affected" % OVAL_NS)
    for platform in affected.findall(".//{%s}platform" % OVAL_NS):
        if(PLATFORMS_RH_EL.__contains__(platform.text)):
            platform_for_el = ET.Element('platform')
            platform_for_el.text = PLATFORMS_RH_EL[platform.text]
            platform_for_el.tail = platform.tail
            affected.append(platform_for_el)

def alter_affected_cpes(definition):
    affected = definition.find(".//{%s}affected_cpe_list" % OVAL_NS)
    for cpe in affected.findall(".//{%s}cpe" % OVAL_NS):
        if(CPES_RH_EL.__contains__(cpe.text)):
            cpe_of_el = ET.Element('cpe')
            cpe_of_el.text = CPES_RH_EL[cpe.text]
            cpe_of_el.tail = cpe.tail
            affected.append(cpe_of_el)

def definitions_for_el(tree_of_tests, tree_of_objects, tree_of_states, defins):
    tst = ET.SubElement(tree_of_tests, "red-def:rpminfo_test", {'check':'at least one','comment':defins['tst_comment'],'id':defins['tst_id'], 'version': RULE_VERSION})
    ET.SubElement(tst, "red-def:object", {'object_ref':defins['obj_id']})
    ET.SubElement(tst, "red-def:state", {'state_ref':defins['ste_id']})
    
    obj = ET.SubElement(tree_of_objects, "red-def:rpminfo_object", {'id':defins['obj_id'], 'version':RULE_VERSION})
    name = ET.SubElement(obj, "red-def:name")
    name.text = defins['obj_name']
    
    stat = ET.SubElement(tree_of_states, "red-def:rpminfo_state", {'id':defins['ste_id'], 'version':RULE_VERSION})
    version = ET.SubElement(stat, "red-def:version", {'operation':'pattern match'})
    version.text = defins['ste_version']

def alter_definition_criterions(definitions, redhat_os_tests, defins_of_el, parent_map):
    for criterion in definitions.findall(".//{%s}criterion" % OVAL_NS):
        test_ref = criterion.attrib['test_ref']    
        if test_ref in redhat_os_tests:
            parent=parent_map[criterion]
            if(parent.attrib['operator'] == "OR"):
                et = ET.Element('criterion', {'comment':defins_of_el['tst_comment'], 'test_ref':defins_of_el['tst_id']})
                et.tail = criterion.tail
                parent.append(et)
            else:
                index = list(parent).index(criterion)
                et = ET.Element('criteria', {'operator':'OR'})
                et.tail = criterion.tail
                et.append(criterion)
                et2 = ET.Element('criterion', {'comment':defins_of_el['tst_comment'], 'test_ref':defins_of_el['tst_id']})
                et.append(et2)
                parent.insert(index, et)
                parent.remove(criterion)
            break
    

def main():
    args = parse_args()
    oval_file = args.oval_file
    oval_output_file = args.output_file
    oval_tree = parse_xml(oval_file)
    oval_root = oval_tree.getroot()

    tree_of_tests = oval_tree.find(".//{%s}tests" % OVAL_NS)
    tree_of_objects = oval_tree.find(".//{%s}objects" % OVAL_NS)
    tree_of_states = oval_tree.find(".//{%s}states" % OVAL_NS)
    
    '''
        修改SIGNATURE_KEYID: 搜索1d51或者7186,添加相应的ste即可
        Ignore redhat master key for el4
        key2:   redhat 6/7/8
        key:    redhat 5
    '''

    SIGN_KEY_STES = { \
        'oval:com.redhat.rhsa:ste:20100889002':'199e2f91fd431d51|24c6a8a7f4a80eb5|0946fca2c105b9de', \
        'oval:com.redhat.rhba:ste:20111656002':'199e2f91fd431d51|24c6a8a7f4a80eb5|0946fca2c105b9de', \
        'oval:com.redhat.rhba:ste:20150364002':'199e2f91fd431d51|24c6a8a7f4a80eb5|0946fca2c105b9de', \
        'oval:com.redhat.rhsa:ste:20190966002':'199e2f91fd431d51|24c6a8a7f4a80eb5|0946fca2c105b9de', \
        'oval:com.redhat.rhba:ste:20070331002':'5326810137017186|a8a447dce8562897', \
        'oval:com.redhat.rhsa:ste:20100889010':'5326810137017186|a8a447dce8562897', \
        'oval:com.redhat.rhsa:ste:20140741002':'5326810137017186|a8a447dce8562897' \
    }

    for ste_id, new_sign_keys in SIGN_KEY_STES.items():
        try:    
            signkey = tree_of_states.find(".//{%s}rpminfo_state[@id='%s']/{%s}signature_keyid" % (OVAL_RED_NS, ste_id, OVAL_RED_NS))
            signkey.set('operation', 'pattern match')
            signkey.text = new_sign_keys
        except:     
            print('red hat sign key: %s not found .\n', ste_id)
            continue


    '''
        添加自定义规则: CentOS-Release检测
    '''
    definitions_for_el(tree_of_tests, tree_of_objects, tree_of_states, DEFINS_OF_EL8)
    definitions_for_el(tree_of_tests, tree_of_objects, tree_of_states, DEFINS_OF_EL7)
    definitions_for_el(tree_of_tests, tree_of_objects, tree_of_states, DEFINS_OF_EL6)
    definitions_for_el(tree_of_tests, tree_of_objects, tree_of_states, DEFINS_OF_EL5)
    
    parent_map = dict((c, p) for p in oval_root.getiterator() for c in p)
    
    '''
        修改definitions
    '''
    for definition in oval_root.findall(".//{%s}definition" % OVAL_NS):
        defin_id = definition.attrib['id']

        '''
            修改platforms & cpe
        '''
        alter_affected_platforms(definition)
        alter_affected_cpes(definition)

        '''
            修改判断条件criteria
        '''
        alter_definition_criterions(definition, redhat_8_tests, DEFINS_OF_EL8, parent_map)
        alter_definition_criterions(definition, redhat_7_tests, DEFINS_OF_EL7, parent_map)
        alter_definition_criterions(definition, redhat_6_tests, DEFINS_OF_EL6, parent_map)
        alter_definition_criterions(definition, redhat_5_tests, DEFINS_OF_EL5, parent_map)


    indent(oval_root)
    oval_tree.write(oval_output_file, encoding="UTF-8", xml_declaration=True)


if __name__ == "__main__":
    main()
