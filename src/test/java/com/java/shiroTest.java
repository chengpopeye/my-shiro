package com.java;

import com.sun.org.apache.bcel.internal.util.ClassPath;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.junit.Test;

import java.util.Arrays;

/**
 * Unit test for simple App.
 */
public class shiroTest {


    /**
     * 自定义realm检查用户拥有权限
     */
    @Test
    public void testHasRoleByRealm() throws Exception {
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro-permission-realm.ini");
        SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("zhangsan", "666");
        subject.login(token);

        // 进行授权操作的前提，用户必须通过认证
        // 判断当前用户是否拥有某个权限，返回true表示拥有指定权限，false表示没有某个权限
        System.out.println(subject.isPermitted("user:delete"));  // true

        // 判断当前用户是否拥有某个角色
        System.out.println(subject.hasRole("role1"));  // true

    }

    @Test
    public void testAouthReaml() {
        //1.创建SecurityManager工厂对象，加载配置文件，创建工厂对象
        // SecurityManager extends Authenticator, Authorizer, SessionManager
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro-permission.ini");
        //2.通过工厂对象，创建SecurityManager对象
        SecurityManager securityManager = factory.getInstance();
        //3.将securityManager绑定到当前运行环境中：让系统随时随地都可以访问securityManager对象
        //静态方法调用
        SecurityUtils.setSecurityManager(securityManager);
        //4.创建当前登录的主体，  此时主体没有经过认证
        Subject subject = SecurityUtils.getSubject();
        //5. 收集主体登录的身份/凭证，即账号密码
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken("zhangsan","666");
        //6.主体登录
        try {
            subject.login(usernamePasswordToken);
        } catch (AuthenticationException e) {
            e.printStackTrace();
        }
        //ini方法检测用户拥有角色
        //7.判断登录是否成功
        System.out.println("验证登录是否成功" + subject.isAuthenticated());

        //进行授权操作时前提：用户必须通过认证

        //ini方式检查用户拥有权限
        //判断当前用户是否拥有某个权限 返回true表示拥有制定权限，false表示没有
        System.out.println(subject.isPermitted("user:delete"));
        //判断当前用户是否拥有一些权限，返回true表示没有，false表示不全部拥有
        System.out.println(subject.isPermittedAll("user:create","user:delete"));
        //返回boolean数组，true表示没有false没有
        //System.out.println(Arrays.toString(subject.isPermitted("","")));
        //没有权限报异常
        //subject.checkPermission("user:list");
    }



    /**
     * 自定义testHashReaml测试
     */
    @Test
    public void testHashReaml() {
        //1.创建SecurityManager工厂对象，加载配置文件，创建工厂对象
        // SecurityManager extends Authenticator, Authorizer, SessionManager
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro-permission.ini");
        //2.通过工厂对象，创建SecurityManager对象
        SecurityManager securityManager = factory.getInstance();
        //3.将securityManager绑定到当前运行环境中：让系统随时随地都可以访问securityManager对象
        //静态方法调用
        SecurityUtils.setSecurityManager(securityManager);
        //4.创建当前登录的主体，  此时主体没有经过认证
        Subject subject = SecurityUtils.getSubject();
        //5. 收集主体登录的身份/凭证，即账号密码
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken("zhangsan","666");
        //6.主体登录
        try {
            subject.login(usernamePasswordToken);
        } catch (AuthenticationException e) {
            e.printStackTrace();
        }
        //ini方法检测用户拥有角色
        //7.判断登录是否成功
        System.out.println("验证登录是否成功" + subject.isAuthenticated());
        //进行授权操作时前提：用户必须通过认证
        //8.判断当前用户是否有一些角色，返回true表示全部有，false表示不全部有
        System.out.println(subject.hasAllRoles(Arrays.asList("role1","role2","role3")));
        //9.判断当前用户是否有一些角色，返回boolean类型数据，true表示拥有全部角色，false表示没有
        System.out.println(Arrays.toString(subject.hasRoles(Arrays.asList("role1", "role2","role3"))));

        //判断当前用户是否拥有某个角色，没有返回值 如果拥有角色，不做任何操作，没有报权限异常
        subject.checkRole("role3");
        //判断当前用户是否拥有一些角色
        subject.checkRoles("role1","role2","role3");
    }



    /**
     * 自定义PassWordReaml测试
     */
    @Test
    public void testLoginByPassWordReaml() {
        //1.创建SecurityManager工厂对象，加载配置文件，创建工厂对象
        // SecurityManager extends Authenticator, Authorizer, SessionManager
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro-cryptography.ini");
        //2.通过工厂对象，创建SecurityManager对象
        SecurityManager securityManager = factory.getInstance();
        //3.将securityManager绑定到当前运行环境中：让系统随时随地都可以访问securityManager对象
        //静态方法调用
        SecurityUtils.setSecurityManager(securityManager);
        //4.创建当前登录的主体，  此时主体没有经过认证
        Subject subject = SecurityUtils.getSubject();
        //5. 收集主体登录的身份/凭证，即账号密码
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken("zhangsan","666");
        //6.主体登录
        try {
            subject.login(usernamePasswordToken);
        } catch (AuthenticationException e) {
            e.printStackTrace();
        }
        //7.判断登录是否成功
        System.out.println("验证登录是否成功" + subject.isAuthenticated());
        //8.登录 (注销)
        subject.logout();
        System.out.println("验证登录是否成功" + subject.isAuthenticated());
    }

    /**
     * shiro测试
     */
    @Test
    public void testShiro() {
        //1.创建SecurityManager工厂对象，加载配置文件，创建工厂对象
        // SecurityManager extends Authenticator, Authorizer, SessionManager
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        //2.通过工厂对象，创建SecurityManager对象
        SecurityManager securityManager = factory.getInstance();
        //3.将securityManager绑定到当前运行环境中：让系统随时随地都可以访问securityManager对象
        //静态方法调用
        SecurityUtils.setSecurityManager(securityManager);
        //4.创建当前登录的主体，  此时主体没有经过认证
        Subject subject = SecurityUtils.getSubject();
        //5. 收集主体登录的身份/凭证，即账号密码
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken("zhangsan","666");
        //6.主体登录
        try {
            subject.login(usernamePasswordToken);
        } catch (AuthenticationException e) {
            e.printStackTrace();
        }
        //7.判断登录是否成功
        System.out.println("验证登录是否成功" + subject.isAuthenticated());
        //8.登录 (注销)
        subject.logout();
        System.out.println("验证登录是否成功" + subject.isAuthenticated());
    }
    /**
     * 自定义reaml测试
     */
    @Test
    public void testLoginByReaml() {
        //1.创建SecurityManager工厂对象，加载配置文件，创建工厂对象
        // SecurityManager extends Authenticator, Authorizer, SessionManager
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro-realm.ini");
        //2.通过工厂对象，创建SecurityManager对象
        SecurityManager securityManager = factory.getInstance();
        //3.将securityManager绑定到当前运行环境中：让系统随时随地都可以访问securityManager对象
        //静态方法调用
        SecurityUtils.setSecurityManager(securityManager);
        //4.创建当前登录的主体，  此时主体没有经过认证
        Subject subject = SecurityUtils.getSubject();
        //5. 收集主体登录的身份/凭证，即账号密码
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken("zhangsan","666");
        //6.主体登录
        try {
            subject.login(usernamePasswordToken);
        } catch (AuthenticationException e) {
            e.printStackTrace();
        }
        //7.判断登录是否成功
        System.out.println("验证登录是否成功" + subject.isAuthenticated());
        //8.登录 (注销)
        subject.logout();
        System.out.println("验证登录是否成功" + subject.isAuthenticated());
    }
}
