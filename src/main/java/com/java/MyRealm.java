package com.java;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

/**
 * Hello world!
 */
public class MyRealm extends AuthorizingRealm {


    //获取名字   一个项目中有多个  区分不同real的值
    @Override
    public String getName() {
        return "MyRealm";
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        return null;
    }

    /**
     * 认证操作
     * @param token
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

        //参数token: 表示登陆时包装的usernamePasswordToken

        //通过用户名到数据库中查用户信息，封装成一个AuthenticationInfo对象返回，方便认证器进行对比
        //获取token中的用户名
        String username = (String) token.getPrincipal(); //多态：向下转 子类 变量名 = (子类)父类;

        //通过用户名查询数据库，将改用户对应数据查询返回：账号与密码
        //假设查询数据库返回数据是：zhangsan 666
        if (!"zhangsan".equals(username)) {
            return null;
        }
        String password = "666";
        //info对象表示realm登陆比对信息：
        //参数1: 用户信息(真是登陆中是登陆对象user对象)
        //参数2：密码  参数3： 当前realm名字
        SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo(username, password, getName());
        return simpleAuthenticationInfo;
    }
}
