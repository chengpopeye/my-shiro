package com.java;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

/**
 * 加密后的realm
 */
public class PassWordRealm extends AuthorizingRealm {

    @Override
    public String getName() {
        return "PassWordRealm";
    }

    /**
     * 授权
     * @param principals
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        return null;
    }

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

        // 模拟数据库中保存加密之后密文: 666 + 账号(盐) + 散列次数
        String password = "cd757bae8bd31da92c6b14c235668091";
        //info对象表示realm登陆比对信息：
        //参数1: 用户信息(真是登陆中是登陆对象user对象)
        //参数2：密码  参数3： salt(盐)
        // 参数4： 当前realm名字
        SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo(username, password, ByteSource.Util.bytes("zhangsan"), getName());
        return simpleAuthenticationInfo;
    }
}
