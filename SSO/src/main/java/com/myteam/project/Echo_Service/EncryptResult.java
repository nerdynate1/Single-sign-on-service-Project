package com.myteam.project.Echo_Service;

public class EncryptResult{
    private String cipherText;
    private String key;
    private String iv;


public EncryptResult(String cipherText, String key, String iv){
    this.cipherText = cipherText;
    this.key = key;
    this.iv = iv;
}

public String getCipherText() {
    return cipherText;
}

public String getKey() {
    return key;
}

public String getIv() {
    return iv;
}
}