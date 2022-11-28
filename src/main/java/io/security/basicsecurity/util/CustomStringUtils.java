package io.security.basicsecurity.util;

public class CustomStringUtils {
    public static boolean isEmptyStr(String str){
        if(str == null) return true;
        else if(str.isBlank()) return true;
        else return false;
    }
}
