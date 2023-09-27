package com.yworks.yguard.ant;

import cn.hutool.core.date.DateUtil;
import cn.hutool.core.io.FileUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.digest.MD5;
import com.yworks.util.abstractjar.Archive;
import com.yworks.util.abstractjar.ArchiveWriter;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.types.ZipFileSet;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class SignSection extends PatternMatchedClassesSection {
  private File jar;
  private String version;
  private File key;
  private String name;
  private List<String> entries;
  private Map<String, byte[]> signatures;

  private MD5 md5 = MD5.create();

  public SignSection() {
    entries = new ArrayList();
    signatures = new HashMap<>();
  }

  public void setJar( final File jar ) {
    this.jar = jar;
  }

  public void setVersion( final String version ) {
    this.version = version;
  }

  public void setKey( final File key ) {
    this.key = key;
  }

  public void setName( final String name ) {
    this.name = name;
  }

  public boolean matches( Archive archive ) {
    return jar.getAbsolutePath().equals(archive.getName());
  }

  public void sign( String inName, String outName, byte[] bytes ) {
    //去文件后缀
    if (inName.contains(".")) {
      inName = inName.substring(0, inName.lastIndexOf("."));
    }
    if (entries.contains(inName)) {
      signatures.put(outName, bytes);
    }
  }

  private String toMd5( byte[] bytes ) {
    //计算md5值
    return md5.digestHex(bytes);
  }

  public void sign( ArchiveWriter outJar ) {
    if (key == null) {
      throw new RuntimeException("签名文件的私钥不能为空");
    }
    if (version == null) {
      throw new RuntimeException("签名文件的版本号不能为空");
    }
    try {
      if (entries.size() != signatures.size()) {
        throw new RuntimeException("签名数量不一致，匹配的文件数: " + entries.size() + ", 签名的文件数: " + signatures.size());
      }
      List<String> classes = new ArrayList<>(signatures.keySet());
      Collections.sort(classes);
      List<String> signs = new ArrayList<String>();
      for (final Object cls : classes) {
        //按顺序计算md5值，需要比对和运行时的是否一致
        byte[] bytes = signatures.get(cls);
        if (bytes.length <= 20000) {
          System.out.println("签名文件: " + cls);
          //每1024字节结算md5
          byte[] b = new byte[1024];
          StringBuilder sb = new StringBuilder();
          for (int i = 0; i < bytes.length; i += 1024) {
            int len = Math.min(1024, bytes.length - i);
            System.arraycopy(bytes, i, b, 0, len);
            sb.append(md5.digestHex(b));
          }
          signs.add(md5.digestHex(sb.toString(), "UTF-8"));
        }
      }
      Collections.sort(signs);
      StringBuilder sb = new StringBuilder();
      for (final String sign : signs) {
        sb.append(sign);
      }
      //计算签名
      String sign = md5.digestHex(sb.toString(), "UTF-8");
      //获取私钥
      byte[] privateKeys = FileUtil.readBytes(key);
      RSA rsa = new RSA(privateKeys, null);
      //加密签名
      sign = rsa.encryptHex(sign, StandardCharsets.UTF_8, KeyType.PrivateKey);
      outJar.addFile(name, (sign + ";" + version + ";" + DateUtil.now()).getBytes(StandardCharsets.UTF_8));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public void createEntries( Collection srcJars, Project project ) {
    for (Iterator it = srcJars.iterator(); it.hasNext(); ) {
      File file = (File) it.next();
      ZipFileSet zipFile = new ZipFileSet();
      zipFile.setProject(project);
      zipFile.setSrc(file);
      try {
        addEntries(entries, zipFile);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    }
  }

  @Override
  public void addEntries( final Collection entries, final String matchedClass ) {
    entries.add(matchedClass);
  }
}
