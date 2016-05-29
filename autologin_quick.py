#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'leohuang'
__date__ = '2016/3/2'
__version__ = '0.1-dev'

import urllib.request, urllib.parse, urllib.error
import re
import requests
import random
import json
import http.cookies as cookielib
import time
import logging
import copy

class QQ_Quick_Login:
    """
    QQ客户端快速登陆:2016.3.2
    算法和实现参考：/ptlogin/ver/10151/js/c_login_1.js
    参考登陆组件：http://ui.ptlogin2.qq.com/cgi-bin/login?hide_title_bar=0&low_login=0&qlogin_auto_login=1&no_verifyimg=1&link_target=blank&appid=636014201&target=self&s_url=http%3A//www.qq.com/qq2012/loginSuccess.htm
    """
    ## default qq info
    appid = 636014201
    action = '2-0-1456213685600'
    urlRaw = "http://ui.ptlogin2.qq.com/cgi-bin/login"
    urlUins = "http://localhost.ptlogin2.qq.com:4300/pt_get_uins"
    urlCheck = 'http://check.ptlogin2.qq.com/check'
    urlSt = "http://localhost.ptlogin2.qq.com:4300/pt_get_st"
    urlQuickLogin = "http://ptlogin2.qq.com/jump"
    urlCheckSig = 'http://check.ptlogin2.qq.com/check_sig'
    urlLogin = 'http://ptlogin2.qq.com/login'
    urlSuccess = 'http://www.qq.com/qq2012/loginSuccess.htm'
    urlQzoneSuccess = 'http://qzs.qq.com/qzone/v5/loginsucc.html?para=izone'
    urlUserQzone = "http://user.qzone.qq.com"
    urlgQzone = "http://g.qzone.qq.com"
    headers = {
            "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Encoding":"gzip, deflate",
            "Accept-Language":"zh-CN,zh;q=0.8,en;q=0.6,zh-TW;q=0.4,ja;q=0.2",
            "Connection":"keep-alive",
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36"
    }


    def __init__(self, uin=None, pwd=None):
        self.uin = uin
        self.pwd = pwd
        self.nick = None
        self.session = requests.Session()
        self.pt_verifysession_v1 = ""
        self.client_type = None

    def run(self):
        '''
        get_signature()
        get_client_uins()
        check_login()
        get_client_pt_get_st()
        quick_login()
        '''

        sig_flag, sig_msg = self.get_signature()
        if sig_flag:
            flag, msg = self.get_client_uins()
            if flag:
                check_flag, check_msg = self.check_login()
                if check_flag:
                    flag, msg = self.get_client_pt_get_st()
                    if flag:
                        #flag, msg = self.quick_login()
                        flag, msg = self.quick_login_qzone()
                        if flag:
                            flag, msg = self.check_login_qzone(msg)
                            if flag:
                                print(("User %s login Ok, nickname: %s" %(self.uin, self.nick)))
                                print( "Cookie info:")
                                for c in self.session.cookies:
                                    print (c)
                                return True
                            else:
                                return False
                        else:
                            print (msg)
                            return False
                    else:
                        print(msg)
                        return False
                else:
                    print(check_msg)
                    return False
            else:
                print(msg)
                return False
        else:
            print(sig_msg)
            return False

    def get_signature(self):
        """
        step 1, load web login iframe and get a login signature
        """
        params = {
            'no_verifyimg': 1,
            "appid": self.appid,
            "s_url": self.urlSuccess,
        }
        params = urllib.parse.urlencode(params)
        url = "%s?%s" %(self.urlRaw, params)
        r = self.session.get(url)
        if 200 != r.status_code:
            error_msg = "[Get signature error] %s %s" %(r.status_code, url)
            return [False, error_msg]
        else:
            #print(r.text)
            self.login_sig = self.session.cookies['pt_login_sig']
            return [True, ""]

    def get_client_uins(self):
        '''
        get client unis info
        need: token check & referer check
        '''
        tk =  "%s%s" %(random.random(), random.randint(1000, 10000) )
        self.session.cookies['pt_local_token'] = tk
        self.session.headers.update({'Referer':'http://ui.ptlogin2.qq.com/'})
        params = {
            'callback':"ptui_getuins_CB",
            'pt_local_tk': tk,
        }
        params = urllib.parse.urlencode(params)
        url = "%s?%s" %(self.urlUins, params)
        try:
            r = self.session.get(url, timeout=120)
            if 200 != r.status_code:
                error_msg = "[Get client unis error] status_code:%s url:%s" %(r.status_code, url)
                print(error_msg)
                return [False, error_msg]
            else:
                print (r.text)
                v_all = re.findall('\{.*?\}', r.text)
                # 多个帐号，取指定的一个
                v_spec = None
                if not self.uin:
                    v_spec = v_all[0]
                    v_spec = json.loads(v_spec)
                else:
                    for v in v_all:
                        v_j = json.loads(v)
                        if v_j["uin"] == self.uin:
                            v_spec = v_j
                            break
                if not v_spec:
                    logging.error("Didn't find valid account:%s ",self.uin)

                self.uin = v_spec["uin"]
                self.client_type = v_spec["client_type"]
                self.nick = v_spec["nickname"]
                #print(self.nick, self.uin)
                return [True, ""]

        except Exception as e:
            error_msg = "[Get client unis error] error:%s url:%s" %(str(e),url)
            return [False, error_msg]


    def check_login(self):
        '''
        step 2: get verifycode and pt_verifysession_v1.
        TX will check username and the login's environment is safe

        example
        requests: http://check.ptlogin2.qq.com/check?regmaster=&pt_tea=1&pt_vcode=1&uin=1802014971&appid=636014201&js_ver=10151&js_type=1&login_sig=YRQ*Xx0x-1yLCn3W0bmxd-Md2*qgxUCe66sH5DFlDLRJMIXvF7WGP0jyLBjkk8f2&u1=http%3A%2F%2Fwww.qq.com%2Fqq2012%2FloginSuccess.htm&r=0.8094342746365941
        response: ptui_checkVC('0','!FKL','\x00\x00\x00\x00\x6b\x68\x90\xfb','025dcaccfbc7ef17ddaf6f2b5b80a37fbe65611d579f893114a984d23c0438c67c53da5525ff368f0224ac62d0d07a1b360a097eac64f219','0');
        '''
        params = {
            "uin": self.uin,
            "appid": self.appid,
            "pt_tea": 1,
            "pt_vcode": 1,
            "js_ver": 10151,
            "js_type": 1,
            "login_sig": self.login_sig,
            "u1": self.urlSuccess,
        }
        params = urllib.parse.urlencode(params)
        url = "%s?%s" %(self.urlCheck, params)
        r = self.session.get(url)
        if 200 != r.status_code:
            error_msg = "[Get verifycode error] %s %s" %(r.status_code, url)
            return [False, error_msg]
        else:
            #print (r.text)
            v = re.findall('\'(.*?)\'', r.text)
            self.check_code = v[0]
            if self.check_code != '0':
                error_msg = "[Verifycode not 0] %s %s" %(self.check_code, url)
                return [False, error_msg]
            self.verifycode = v[1]
            self.salt = v[2]
            self.pt_verifysession_v1 = v[3]
            #pprint(v)
            return [True, ""]

    def get_client_pt_get_st(self):
        '''
        get client key
        '''

        params = {
            'clientuin': self.uin,
            'callback': 'ptui_getst_CB',
            'pt_local_tk': self.session.cookies['pt_local_token'],
        }
        params = urllib.parse.urlencode(params)
        url = "%s?%s" %(self.urlSt, params)
        try:
            r = self.session.get(url, timeout=120)
            if 200 != r.status_code:
                error_msg = "[Get client st error] %s %s" %(r.status_code, url)
                print(error_msg)
                return [False, error_msg]
            else:
                #print(r.text)
                self.clientkey = self.session.cookies["clientkey"]
                #pprint(v)
                return [True, ""]
        except Exception as e:
            error_msg = "[Get client st error] %s %s" %(url, str(e))
            return [False, error_msg]

    def quick_login(self):
        params = {
            "clientuin": self.uin,
            "keyindex": '9',
            "pt_aid": self.appid,
            "u1": self.urlSuccess,
            "pt_local_tk": self.session.cookies["pt_local_token"],
            "pt_3rd_aid": 0,
            "ptopt": 1,
            "style": 20,
        }
        print ("quick_login:")
        params = urllib.parse.urlencode(params)
        url = "%s?%s" %(self.urlQuickLogin, params)
        #print (url)
        r = self.session.get(url, timeout=120)
        if 200 != r.status_code:
            error_msg = "[Get client st error] %s %s" %(r.status_code, url)
            print(error_msg)
            return [False, error_msg]
        else:
            #print (r.text)
            v = re.findall('\'(.*?)\'', r.text)
            if v[0] != '0':
                error_msg = "[Quick Login Faild] %s %s" %(url, v[4])
                return [False, error_msg]
            return [True, ""]

    def quick_login_qzone(self):
        params = {
            "clientuin": self.uin,
            "keyindex": '9',
            "daid": 5,
            "pt_aid": self.appid,
            "u1": self.urlQzoneSuccess,
            "pt_local_tk": self.session.cookies["pt_local_token"],
            "pt_3rd_aid": 0,
            "ptopt": 1,
            "style": 40,
        }
        params = urllib.parse.urlencode(params)
        url = "%s?%s" %(self.urlQuickLogin, params)
        #print (url)
        r = self.session.get(url, timeout=120)
        if 200 != r.status_code:
            error_msg = "[Get client st error] %s %s" %(r.status_code, url)
            print(error_msg)
            return [False, error_msg]
        else:
            #print (r.text)
            v = re.findall('\'(.*?)\'', r.text)
            if v[0] != '0':
                error_msg = "[Quick Login Faild] %s %s" %(url, v[4])
                return [False, error_msg]
            return [True, v[1]]

    def check_login_qzone(self,url):
        r = self.session.get(url, timeout=120,)
        if 200 != r.status_code:
            error_msg = "[login_qone error] %s %s" %(r.status_code, url)
            print(error_msg)
            return [False, error_msg]
        else:
            #print (r.text)
            GMT_FORMAT = '%a, %d-%b-%Y %H:%M:%S GMT'
            timeout_time = time.time()+300000
            timeout = time.strftime(GMT_FORMAT,time.localtime(timeout_time))
            raw_cookie = 'fnc=2; path=/; domain=qzone.qq.com; expires=' + timeout + ';'
            simp_cookie = cookielib.SimpleCookie(raw_cookie)
            self.session.cookies.update(simp_cookie)
            print("Login qzone success!")
            return [True,r.text]


    def touch_qzone(self,target_qq_number):
        '''
        :param target_qq_number:
        :return:
        '''
        headers = {
            "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Encoding":"gzip, deflate, sdch",
            "Accept-Language":"zh-CN,zh;q=0.8,en;q=0.6,zh-TW;q=0.4,ja;q=0.2",
            "Connection":"keep-alive",
            "Upgrade-Insecure-Requests":"1",
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36"
        }
        url = "%s/%s/%s" %(self.urlUserQzone,target_qq_number,"main")
        #print url
        r = self.session.get(url, timeout=120, headers=headers)
        if 200 != r.status_code:
            error_msg = "[Get client st error] %s %s" %(r.status_code, url)
            print(error_msg)
            return [False, error_msg]
        else:
            #print(r.text)
            #g_ISP 关键字
            return [True,r.text]

    def getACSRFToken(self,url):
        url = urllib.parse.urlparse(url)
        skey=None
        if url:
            if url.hostname and url.hostname.find("qzone.qq.com"):
                skey = self.session.cookies["p_skey"]
            elif url.hostname and url.hostname.find("qq.com"):
                skey=self.session.cookies["skey"]
            if not skey:
                self.session.cookies["p_skey"]
        if not skey:
            skey = self.session.cookies["skey"]
        if not skey:
            skey = self.session.cookies["rv2"]
        hash_v = 5381;
        for idx in range(0,len(skey)):
            uni_v = skey[idx]
            uni_v = ord(uni_v)
            hash_v += (hash_v << 5) + uni_v
        return hash_v & 2147483647


    def request_emotion(self,target_qq_number):
        '''
        增加访问记录
        :param target_qq_number:
        :return:
        '''
        headers = {
            "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Encoding":"gzip, deflate",
            "Accept-Language":"zh-CN,zh;q=0.8,en;q=0.6,zh-TW;q=0.4,ja;q=0.2",
            "Connection":"keep-alive",
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36"
        }
        rd =  "%s" %(random.random())
        g_tk = self.getACSRFToken(self.urlUserQzone)
        params = {
            "uin": target_qq_number,
            "loginUin" : self.uin,
            "num" :3,
            "noflower": 1,
            "rd": rd,
            "g_tk":g_tk
        }
        params = urllib.parse.urlencode(params)
        x_real_url = "%s/%s?%s" %(self.urlgQzone,"fcg-bin/cgi_emotion_list.fcg",params)
        r = self.session.get(x_real_url, timeout=120, headers=headers)
        if 200 != r.status_code:
            error_msg = "[Get emotion error] %s %s" %(r.status_code, x_real_url)
            print(error_msg)
            return [False, error_msg]
        else:
            print(x_real_url)
            print(r.text)
            return [True,r.text]

    def parse_callback(self,ori_data):
        if ori_data:
            start_ =ori_data.find('(')
            end_=ori_data.rfind(')')
            if start_>=0 and end_ >= 0:
                real_data = ori_data[start_+1:end_]
                data=eval(real_data)
                if data["code"]==0:
                    return [True,data]
                else:
                    logging.error(data)
                    #抱歉，服务繁忙，请稍后再试。
                    if data['code']==-4016:
                        return [False,data['code']]
        return [False,""]

    def parse_visitors(self,ori_data):
        visitor = []
        resp,data = self.parse_callback(ori_data)
        if resp:
            data = data["data"]["items"]
            for ele in data:
                visitor.append({'name':ele['name'],'uin':ele['uin']})
            return [True,visitor]
        else:
            return [resp,data]


    def get_visitor(self,target_qq_number):
        g_tk = self.getACSRFToken(self.urlUserQzone)
        params = {
            "uin":target_qq_number,
            "mask" :2,
            "mod":2,
            "fupdate":1,
            "g_tk":g_tk
        }
        params = urllib.parse.urlencode(params)
        url = "%s/%s?%s" %("https://h5s.qzone.qq.com","proxy/domain/g.qzone.qq.com/cgi-bin/friendshow/cgi_get_visitor_simple",params)
        print(url)

        r = self.session.get(url, timeout=120, headers=self.headers)
        if 200 != r.status_code:
            error_msg = "[Get visitor list error] %s %s" %(r.status_code, url)
            print(error_msg)
            return [False, error_msg]
        else:
            _data = r.text
            return self.parse_visitors(_data)

    def get_uins_in_comments(self,common_list,exist_uins=[]):
        visitors = []
        for ele in common_list:
            if "uin" in ele and int(ele['uin']) not in exist_uins:
                visitors.append({'name':ele['nickname'],'uin':ele['uin']})
                exist_uins.append(int(ele['uin']))
            if "replyList" in ele and len(ele["replyList"])>0:
                reply_list = ele["replyList"]
                res,inner_vistors = self.get_uins_in_comments(reply_list,exist_uins)
                if len(inner_vistors)>0:
                    visitors.extend(inner_vistors)
        return [True,visitors]

    def parse_comments(self,ori_data):
        '''
        :param ori_data:
        :return:
        '''
        visitor = []
        resp,data = self.parse_callback(ori_data)
        exist_uins=[]
        if resp:
            total = data["data"]["total"]
            comment_list = data["data"]["commentList"]
            resp,visitor = self.get_uins_in_comments(comment_list,exist_uins)
        return [resp,visitor]


    def get_message(self,target_uin):
        '''
        获取留言板内容。
        http://m.qzone.qq.com/cgi-bin/new/get_msgb', {
		uin : LOGIN_UIN,
		hostUin : SPACE_UIN,
		start : start,
		s : Math.random(),
		format : 'jsonp',
		num : 10,
		inCharset : 'utf-8',
		outCharset : 'utf-8'
        :param target_uin:
        :return:
        '''
        g_tk = self.getACSRFToken(self.urlUserQzone)
        params = {
            "uin":self.uin,
            "hostUin":target_uin,
            "start" :0,
            "s":random.random(),
            "format":'jsonp',
            "num" : 10,
            "inCharset" : 'utf-8',
            "outCharset" : 'utf-8',
            "g_tk":g_tk
        }
        params = urllib.parse.urlencode(params)
        url = "%s/%s?%s" %("http://m.qzone.qq.com","cgi-bin/new/get_msgb",params)
        print(url)
        r = self.session.get(url, timeout=120, headers=self.headers)
        if 200 != r.status_code:
            error_msg = "[Get visitor list error] %s %s" %(r.status_code, url)
            print(error_msg)
            return [False, error_msg]
        else:
            _data = r.text
            return self.parse_comments(_data)

    def get_visitor_tree(self,root_uin_num,skip_uins=None):
        root_uin = {'uin':root_uin_num,'name':""}
        visitied_uins_number=[]
        valid_uins= []
        new_uins=[root_uin]
        end=None
        while(not end):
            inner_new_uin = []
            for uin in new_uins:
                res,r = qlogin.get_visitor(uin['uin'])
                #频繁访问会被block
                time.sleep(1)
                visitied_uins_number.append(int(uin['uin']))
                if res:
                    valid_uins.append(uin)
                    for sub_uin in r:
                        sub_uin_int = int(sub_uin['uin'])
                        if ( sub_uin_int not in visitied_uins_number) and (sub_uin_int not in skip_uins):
                            inner_new_uin.append(sub_uin)
                elif isinstance(r,int) and r == -4016:
                    end = True
                    break

            if len(inner_new_uin)==0 or len(visitied_uins_number)>10000:
                end = True
            else:
                new_uins = copy.deepcopy(inner_new_uin)
        print(visitied_uins_number)
        return [True,valid_uins]


qlogin = QQ_Quick_Login()
status = qlogin.run()

target_number = ""
if status:
    #res,r = qlogin.request_emotion(target_number)
    skip_uins = []
    #res,r = qlogin.get_visitor_tree(target_number,skip_uins)
    res,r = qlogin.get_message(target_number)
    f = open("data/result.text","w",encoding='utf-8')
    f.write(str(r))
    f.close()

