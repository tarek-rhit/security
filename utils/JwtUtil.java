package com.ia.iatt.security.utils;

public class JwtUtil {
    public  static  final String  SECRET="IA2022PFE";
    public  static  final String  AUTH_HEADER="Authorization";
    public  static  final long  EXPIRE_ACCESS_TOKEN=15*60*1000;
    public static final long EXPIRE_REFRESH_TOKEN =15*60*1000 ;
    public static final String  PREFIX = "Bearer ";
    public static final String  GET_ARRAYS_LLC = "Get Arrays, LLC";
    public static final String  GET_ARRAYS_Administrations = "User Management Portail";
    public static final String  AUTHORITHIES = "authorities";
    public static final String  FORBIDDEN_MESSAGE = "you need to log in to access this page";
    public static final String  Acces_DENIED_MESSAGE = "you do not have permission to access this page";
    public static final String  OPTIONS_HTTP_METHOD = "options";
    public static final String[]  PUBLIC8URLS = {"/login"};


    public static final String TOKEN_CANNOT_BE_VERIFEID = "token cannot be verified";
}
