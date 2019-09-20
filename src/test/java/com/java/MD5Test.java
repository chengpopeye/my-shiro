package com.java;

import org.apache.shiro.crypto.hash.Md5Hash;
import org.junit.Test;

public class MD5Test {

    @Test
    public void testMD5() {
        String password = "666"; //密码 明文
        //加密: md5
        Md5Hash md5Hash = new Md5Hash(password);
        //md5Hash = fae0b27c451c728867a567e8c1bb4e53
        System.out.println("md5Hash = " + md5Hash);
        //加密：md5 + salt(盐)
        md5Hash = new Md5Hash(password ,"zhengsan");
        //md5Hash + salt = 3b3daad1f901e41c4205071ca145d941
        System.out.println("md5Hash + salt = " + md5Hash);
        // 加密：md5 + salt + 散列次数
        md5Hash = new Md5Hash(password,"zhangsan",3);
        // md5Hash + 散列次数  + sal = cd757bae8bd31da92c6b14c235668091
        System.out.println("md5Hash + 散列次数  + sal = " + md5Hash);
    }
}
