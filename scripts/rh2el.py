#!/usr/bin/env python2
# -*- coding:utf8 -*-

'''
Descripts: Convert Redhat OVAL to Enterprise Linux
Author: Sep0lkit
Version: 2.1
Update: 2022/01/13
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
ET.register_namespace('ind-def', "http://oval.mitre.org/XMLSchema/oval-definitions-5#independent")
ET.register_namespace('unix-def', "http://oval.mitre.org/XMLSchema/oval-definitions-5#unix")
ET.register_namespace('red-def', "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux")

OVAL_NS = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
OVAL_RED_NS = "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"

'''
    Global Variables
'''
PLATFORMS_RH_EL = {'Red Hat Enterprise Linux 8':'Community Enterprise Operating System 8','Red Hat Enterprise Linux 7':'Community Enterprise Operating System 7','Red Hat Enterprise Linux 6':'Community Enterprise Operating System 6','Red Hat Enterprise Linux 5':'Community Enterprise Operating System 5'}

CPES_RH_EL = {'cpe:/o:redhat:enterprise_linux:8':'cpe:/o:centos:centos:8','cpe:/o:redhat:enterprise_linux:7':'cpe:/o:centos:centos:7','cpe:/o:redhat:enterprise_linux:6':'cpe:/o:centos:centos:6','cpe:/o:redhat:enterprise_linux:5':'cpe:/o:centos:centos:5','cpe:/a:redhat:enterprise_linux:8':'cpe:/a:centos:centos:8'}


''' 
    Custom Defines for CentOS
'''

RULE_VERSION = '101'

DEFINS_OF_EL = {'tst_comment':'CentOS is installed', 'tst_id':'oval:com.github.sep0lkit:tst:190630000', 'tst_check':'none satisfy', 'obj_id':'oval:com.github.sep0lkit:obj:190630000', 'ste_id':'oval:com.github.sep0lkit:ste:190630000', 'obj_name':'centos-release', 'obj_filepath':'/etc/redhat-release'}

DEFINS_OF_EL5 = {'tst_comment':'CentOS 5 is installed', 'tst_id':'oval:com.github.sep0lkit:tst:190630001', 'tst_check':'at least one', 'obj_id':'oval:com.github.sep0lkit:obj:190630001', 'ste_id':'oval:com.github.sep0lkit:ste:190630001', 'obj_name':'centos-release', 'obj_filepath':'/etc/redhat-release', 'ste_version':'^5' }

DEFINS_OF_EL6 = {'tst_comment':'CentOS 6 is installed', 'tst_id':'oval:com.github.sep0lkit:tst:190630002', 'tst_check':'at least one', 'obj_id':'oval:com.github.sep0lkit:obj:190630002', 'ste_id':'oval:com.github.sep0lkit:ste:190630002', 'obj_name':'centos-release', 'obj_filepath':'/etc/redhat-release', 'ste_version':'^6' }

DEFINS_OF_EL7 = {'tst_comment':'CentOS 7 is installed', 'tst_id':'oval:com.github.sep0lkit:tst:190630003', 'tst_check':'at least one', 'obj_id':'oval:com.github.sep0lkit:obj:190630003', 'ste_id':'oval:com.github.sep0lkit:ste:190630003', 'obj_name':'centos-release', 'obj_filepath':'/etc/redhat-release', 'ste_version':'^7' }

DEFINS_OF_EL8 = {'tst_comment':'CentOS 8 is installed', 'tst_id':'oval:com.github.sep0lkit:tst:190630004', 'tst_check':'at least one', 'obj_id':'oval:com.github.sep0lkit:obj:190630004', 'ste_id':'oval:com.github.sep0lkit:ste:190630004', 'obj_name':'centos-release', 'obj_filepath':'/etc/redhat-release', 'ste_version':'^8' }


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
    tst = ET.SubElement(tree_of_tests, "red-def:rpmverifyfile_test", {'check':defins['tst_check'],'comment':defins['tst_comment'],'id':defins['tst_id'], 'version': RULE_VERSION})
    ET.SubElement(tst, "red-def:object", {'object_ref':defins['obj_id']})
    ET.SubElement(tst, "red-def:state", {'state_ref':defins['ste_id']})
    
    obj = ET.SubElement(tree_of_objects, "red-def:rpmverifyfile_object", {'id':defins['obj_id'], 'version':RULE_VERSION})
    behaviors = ET.SubElement(obj, "red-def:behaviors noconfigfiles='true' noghostfiles='true' nogroup='true' nolinkto='true' nomd5='true' nomode='true' nomtime='true' nordev='true' nosize='true' nouser='true'")
    name = ET.SubElement(obj, "red-def:name", {'operation':'pattern match'})
    epoch = ET.SubElement(obj, "red-def:epoch", {'operation':'pattern match'})
    version = ET.SubElement(obj, "red-def:version", {'operation':'pattern match'})
    release = ET.SubElement(obj, "red-def:release", {'operation':'pattern match'})
    arch = ET.SubElement(obj, "red-def:arch", {'operation':'pattern match'})
    filepath = ET.SubElement(obj, "red-def:filepath")
    filepath.text = defins['obj_filepath']
    
    stat = ET.SubElement(tree_of_states, "red-def:rpmverifyfile_state", {'id':defins['ste_id'], 'version':RULE_VERSION})
    name = ET.SubElement(stat, "red-def:name", {'operation':'pattern match'})
    name.text = '^centos(-linux)?-release'
    try:
        defins['ste_version']
    except:
        print("WARN: os ste, don't need version for ste " + defins['ste_id'])
    else:
        version = ET.SubElement(stat, "red-def:version", {'operation':'pattern match'})
        version.text = defins['ste_version']

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
        'oval:com.redhat.rhsa:ste:20140741002':'5326810137017186|a8a447dce8562897', \
	'oval:com.redhat.rhba:ste:20191992002':'199e2f91fd431d51|05b555b38483c65d' \
    }

    for ste_id, new_sign_keys in SIGN_KEY_STES.items():
        try:    
            signkey = tree_of_states.find(".//{%s}rpminfo_state[@id='%s']/{%s}signature_keyid" % (OVAL_RED_NS, ste_id, OVAL_RED_NS))
            signkey.set('operation', 'pattern match')
            signkey.text = new_sign_keys
        except:     
            print('WARN: red hat sign key: %s not found' % ste_id)
            continue


    '''
        添加自定义规则: CentOS-Release检测
    '''
    definitions_for_el(tree_of_tests, tree_of_objects, tree_of_states, DEFINS_OF_EL)

    definitions_for_el(tree_of_tests, tree_of_objects, tree_of_states, DEFINS_OF_EL8)
    definitions_for_el(tree_of_tests, tree_of_objects, tree_of_states, DEFINS_OF_EL7)
    definitions_for_el(tree_of_tests, tree_of_objects, tree_of_states, DEFINS_OF_EL6)
    definitions_for_el(tree_of_tests, tree_of_objects, tree_of_states, DEFINS_OF_EL5)
    
    
    '''
        modify definitions
    '''
    for definition in oval_root.findall(".//{%s}definition" % OVAL_NS):
        defin_id = definition.attrib['id']

        '''
            modify platforms & cpe
        '''
        alter_affected_platforms(definition)
        alter_affected_cpes(definition)

        '''
            modify criterion
        '''
        for criterion in definition.findall(".//{%s}criterion" % OVAL_NS):
            tst_comment = criterion.attrib['comment']    
            if tst_comment == "Red Hat Enterprise Linux must be installed" :
                criterion.set('comment',  DEFINS_OF_EL['tst_comment'])
                criterion.set('test_ref', DEFINS_OF_EL['tst_id'])
            elif tst_comment == "Red Hat Enterprise Linux 8 is installed" :
                criterion.set('comment',  DEFINS_OF_EL8['tst_comment'])
                criterion.set('test_ref', DEFINS_OF_EL8['tst_id'])
            elif tst_comment == "Red Hat Enterprise Linux 7 is installed" :
                criterion.set('comment',  DEFINS_OF_EL7['tst_comment'])
                criterion.set('test_ref', DEFINS_OF_EL7['tst_id'])
            elif tst_comment == "Red Hat Enterprise Linux 6 is installed" :
                criterion.set('comment',  DEFINS_OF_EL6['tst_comment'])
                criterion.set('test_ref', DEFINS_OF_EL6['tst_id'])
            elif tst_comment == "Red Hat Enterprise Linux 5 is installed" :
                criterion.set('comment',  DEFINS_OF_EL5['tst_comment'])
                criterion.set('test_ref', DEFINS_OF_EL5['tst_id'])

    indent(oval_root)
    oval_tree.write(oval_output_file, encoding="UTF-8", xml_declaration=True)


if __name__ == "__main__":
    main()
