 Save This PageHome » openjdk-7 » sun.security » tools » [javadoc | source]
    1   /*
    2    * Copyright (c) 1997, 2011, Oracle and/or its affiliates. All rights reserved.
    3    * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
    4    *
    5    * This code is free software; you can redistribute it and/or modify it
    6    * under the terms of the GNU General Public License version 2 only, as
    7    * published by the Free Software Foundation.  Oracle designates this
    8    * particular file as subject to the "Classpath" exception as provided
    9    * by Oracle in the LICENSE file that accompanied this code.
   10    *
   11    * This code is distributed in the hope that it will be useful, but WITHOUT
   12    * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
   13    * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
   14    * version 2 for more details (a copy is included in the LICENSE file that
   15    * accompanied this code).
   16    *
   17    * You should have received a copy of the GNU General Public License version
   18    * 2 along with this work; if not, write to the Free Software Foundation,
   19    * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
   20    *
   21    * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
   22    * or visit www.oracle.com if you need additional information or have any
   23    * questions.
   24    */
   25   
   26   package sun.security.tools;
   27   
   28   import java.io;
   29   import java.security.CodeSigner;
   30   import java.security.KeyStore;
   31   import java.security.KeyStoreException;
   32   import java.security.MessageDigest;
   33   import java.security.Key;
   34   import java.security.PublicKey;
   35   import java.security.PrivateKey;
   36   import java.security.Security;
   37   import java.security.Signature;
   38   import java.security.Timestamp;
   39   import java.security.UnrecoverableEntryException;
   40   import java.security.UnrecoverableKeyException;
   41   import java.security.Principal;
   42   import java.security.Provider;
   43   import java.security.cert.Certificate;
   44   import java.security.cert.CertificateFactory;
   45   import java.security.cert.CRL;
   46   import java.security.cert.X509Certificate;
   47   import java.security.cert.CertificateException;
   48   import java.text.Collator;
   49   import java.text.MessageFormat;
   50   import java.util;
   51   import java.util.jar.JarEntry;
   52   import java.util.jar.JarFile;
   53   import java.lang.reflect.Constructor;
   54   import java.math.BigInteger;
   55   import java.net.URI;
   56   import java.net.URL;
   57   import java.net.URLClassLoader;
   58   import java.security.cert.CertStore;
   59   
   60   import java.security.cert.X509CRL;
   61   import java.security.cert.X509CRLEntry;
   62   import java.security.cert.X509CRLSelector;
   63   import javax.security.auth.x500.X500Principal;
   64   import sun.misc.BASE64Encoder;
   65   import sun.security.util.ObjectIdentifier;
   66   import sun.security.pkcs.PKCS10;
   67   import sun.security.provider.X509Factory;
   68   import sun.security.util.Password;
   69   import sun.security.util.PathList;
   70   import javax.crypto.KeyGenerator;
   71   import javax.crypto.SecretKey;
   72   
   73   import javax.net.ssl.HostnameVerifier;
   74   import javax.net.ssl.HttpsURLConnection;
   75   import javax.net.ssl.SSLContext;
   76   import javax.net.ssl.SSLSession;
   77   import javax.net.ssl.TrustManager;
   78   import javax.net.ssl.X509TrustManager;
   79   import sun.misc.BASE64Decoder;
   80   import sun.security.pkcs.PKCS10Attribute;
   81   import sun.security.pkcs.PKCS9Attribute;
   82   import sun.security.provider.certpath.ldap.LDAPCertStoreHelper;
   83   import sun.security.util.DerValue;
   84   import sun.security.x509;
   85   
   86   import static java.security.KeyStore.*;
   87   import static sun.security.tools.KeyTool.Command.*;
   88   import static sun.security.tools.KeyTool.Option.*;
   89   
   90   /**
   91    * This tool manages keystores.
   92    *
   93    * @author Jan Luehe
   94    *
   95    *
   96    * @see java.security.KeyStore
   97    * @see sun.security.provider.KeyProtector
   98    * @see sun.security.provider.JavaKeyStore
   99    *
  100    * @since 1.2
  101    */
  102   public final class KeyTool {
  103   
  104       private boolean debug = false;
  105       private Command command = null;
  106       private String sigAlgName = null;
  107       private String keyAlgName = null;
  108       private boolean verbose = false;
  109       private int keysize = -1;
  110       private boolean rfc = false;
  111       private long validity = (long)90;
  112       private String alias = null;
  113       private String dname = null;
  114       private String dest = null;
  115       private String filename = null;
  116       private String infilename = null;
  117       private String outfilename = null;
  118       private String srcksfname = null;
  119   
  120       // User-specified providers are added before any command is called.
  121       // However, they are not removed before the end of the main() method.
  122       // If you're calling KeyTool.main() directly in your own Java program,
  123       // please programtically add any providers you need and do not specify
  124       // them through the command line.
  125   
  126       private Set<Pair <String, String>> providers = null;
  127       private String storetype = null;
  128       private String srcProviderName = null;
  129       private String providerName = null;
  130       private String pathlist = null;
  131       private char[] storePass = null;
  132       private char[] storePassNew = null;
  133       private char[] keyPass = null;
  134       private char[] keyPassNew = null;
  135       private char[] newPass = null;
  136       private char[] destKeyPass = null;
  137       private char[] srckeyPass = null;
  138       private String ksfname = null;
  139       private File ksfile = null;
  140       private InputStream ksStream = null; // keystore stream
  141       private String sslserver = null;
  142       private String jarfile = null;
  143       private KeyStore keyStore = null;
  144       private boolean token = false;
  145       private boolean nullStream = false;
  146       private boolean kssave = false;
  147       private boolean noprompt = false;
  148       private boolean trustcacerts = false;
  149       private boolean protectedPath = false;
  150       private boolean srcprotectedPath = false;
  151       private CertificateFactory cf = null;
  152       private KeyStore caks = null; // "cacerts" keystore
  153       private char[] srcstorePass = null;
  154       private String srcstoretype = null;
  155       private Set<char[]> passwords = new HashSet<>();
  156       private String startDate = null;
  157   
  158       private List<String> ids = new ArrayList<>();   // used in GENCRL
  159       private List<String> v3ext = new ArrayList<>();
  160   
  161       enum Command {
  162           CERTREQ("Generates.a.certificate.request",
  163               ALIAS, SIGALG, FILEOUT, KEYPASS, KEYSTORE, DNAME,
  164               STOREPASS, STORETYPE, PROVIDERNAME, PROVIDERCLASS,
  165               PROVIDERARG, PROVIDERPATH, V, PROTECTED),
  166           CHANGEALIAS("Changes.an.entry.s.alias",
  167               ALIAS, DESTALIAS, KEYPASS, KEYSTORE, STOREPASS,
  168               STORETYPE, PROVIDERNAME, PROVIDERCLASS, PROVIDERARG,
  169               PROVIDERPATH, V, PROTECTED),
  170           DELETE("Deletes.an.entry",
  171               ALIAS, KEYSTORE, STOREPASS, STORETYPE,
  172               PROVIDERNAME, PROVIDERCLASS, PROVIDERARG,
  173               PROVIDERPATH, V, PROTECTED),
  174           EXPORTCERT("Exports.certificate",
  175               RFC, ALIAS, FILEOUT, KEYSTORE, STOREPASS,
  176               STORETYPE, PROVIDERNAME, PROVIDERCLASS, PROVIDERARG,
  177               PROVIDERPATH, V, PROTECTED),
  178           GENKEYPAIR("Generates.a.key.pair",
  179               ALIAS, KEYALG, KEYSIZE, SIGALG, DESTALIAS, DNAME,
  180               STARTDATE, EXT, VALIDITY, KEYPASS, KEYSTORE,
  181               STOREPASS, STORETYPE, PROVIDERNAME, PROVIDERCLASS,
  182               PROVIDERARG, PROVIDERPATH, V, PROTECTED),
  183           GENSECKEY("Generates.a.secret.key",
  184               ALIAS, KEYPASS, KEYALG, KEYSIZE, KEYSTORE,
  185               STOREPASS, STORETYPE, PROVIDERNAME, PROVIDERCLASS,
  186               PROVIDERARG, PROVIDERPATH, V, PROTECTED),
  187           GENCERT("Generates.certificate.from.a.certificate.request",
  188               RFC, INFILE, OUTFILE, ALIAS, SIGALG, DNAME,
  189               STARTDATE, EXT, VALIDITY, KEYPASS, KEYSTORE,
  190               STOREPASS, STORETYPE, PROVIDERNAME, PROVIDERCLASS,
  191               PROVIDERARG, PROVIDERPATH, V, PROTECTED),
  192           IMPORTCERT("Imports.a.certificate.or.a.certificate.chain",
  193               NOPROMPT, TRUSTCACERTS, PROTECTED, ALIAS, FILEIN,
  194               KEYPASS, KEYSTORE, STOREPASS, STORETYPE,
  195               PROVIDERNAME, PROVIDERCLASS, PROVIDERARG,
  196               PROVIDERPATH, V),
  197           IMPORTKEYSTORE("Imports.one.or.all.entries.from.another.keystore",
  198               SRCKEYSTORE, DESTKEYSTORE, SRCSTORETYPE,
  199               DESTSTORETYPE, SRCSTOREPASS, DESTSTOREPASS,
  200               SRCPROTECTED, SRCPROVIDERNAME, DESTPROVIDERNAME,
  201               SRCALIAS, DESTALIAS, SRCKEYPASS, DESTKEYPASS,
  202               NOPROMPT, PROVIDERCLASS, PROVIDERARG, PROVIDERPATH,
  203               V),
  204           KEYPASSWD("Changes.the.key.password.of.an.entry",
  205               ALIAS, KEYPASS, NEW, KEYSTORE, STOREPASS,
  206               STORETYPE, PROVIDERNAME, PROVIDERCLASS, PROVIDERARG,
  207               PROVIDERPATH, V),
  208           LIST("Lists.entries.in.a.keystore",
  209               RFC, ALIAS, KEYSTORE, STOREPASS, STORETYPE,
  210               PROVIDERNAME, PROVIDERCLASS, PROVIDERARG,
  211               PROVIDERPATH, V, PROTECTED),
  212           PRINTCERT("Prints.the.content.of.a.certificate",
  213               RFC, FILEIN, SSLSERVER, JARFILE, V),
  214           PRINTCERTREQ("Prints.the.content.of.a.certificate.request",
  215               FILEIN, V),
  216           PRINTCRL("Prints.the.content.of.a.CRL.file",
  217               FILEIN, V),
  218           STOREPASSWD("Changes.the.store.password.of.a.keystore",
  219               NEW, KEYSTORE, STOREPASS, STORETYPE, PROVIDERNAME,
  220               PROVIDERCLASS, PROVIDERARG, PROVIDERPATH, V),
  221   
  222           // Undocumented start here, KEYCLONE is used a marker in -help;
  223   
  224           KEYCLONE("Clones.a.key.entry",
  225               ALIAS, DESTALIAS, KEYPASS, NEW, STORETYPE,
  226               KEYSTORE, STOREPASS, PROVIDERNAME, PROVIDERCLASS,
  227               PROVIDERARG, PROVIDERPATH, V),
  228           SELFCERT("Generates.a.self.signed.certificate",
  229               ALIAS, SIGALG, DNAME, STARTDATE, VALIDITY, KEYPASS,
  230               STORETYPE, KEYSTORE, STOREPASS, PROVIDERNAME,
  231               PROVIDERCLASS, PROVIDERARG, PROVIDERPATH, V),
  232           GENCRL("Generates.CRL",
  233               RFC, FILEOUT, ID,
  234               ALIAS, SIGALG, EXT, KEYPASS, KEYSTORE,
  235               STOREPASS, STORETYPE, PROVIDERNAME, PROVIDERCLASS,
  236               PROVIDERARG, PROVIDERPATH, V, PROTECTED),
  237           IDENTITYDB("Imports.entries.from.a.JDK.1.1.x.style.identity.database",
  238               FILEIN, STORETYPE, KEYSTORE, STOREPASS, PROVIDERNAME,
  239               PROVIDERCLASS, PROVIDERARG, PROVIDERPATH, V);
  240   
  241           final String description;
  242           final Option[] options;
  243           Command(String d, Option... o) {
  244               description = d;
  245               options = o;
  246           }
  247           @Override
  248           public String toString() {
  249               return "-" + name().toLowerCase(Locale.ENGLISH);
  250           }
  251       };
  252   
  253       enum Option {
  254           ALIAS("alias", "<alias>", "alias.name.of.the.entry.to.process"),
  255           DESTALIAS("destalias", "<destalias>", "destination.alias"),
  256           DESTKEYPASS("destkeypass", "<arg>", "destination.key.password"),
  257           DESTKEYSTORE("destkeystore", "<destkeystore>", "destination.keystore.name"),
  258           DESTPROTECTED("destprotected", null, "destination.keystore.password.protected"),
  259           DESTPROVIDERNAME("destprovidername", "<destprovidername>", "destination.keystore.provider.name"),
  260           DESTSTOREPASS("deststorepass", "<arg>", "destination.keystore.password"),
  261           DESTSTORETYPE("deststoretype", "<deststoretype>", "destination.keystore.type"),
  262           DNAME("dname", "<dname>", "distinguished.name"),
  263           EXT("ext", "<value>", "X.509.extension"),
  264           FILEOUT("file", "<filename>", "output.file.name"),
  265           FILEIN("file", "<filename>", "input.file.name"),
  266           ID("id", "<id:reason>", "Serial.ID.of.cert.to.revoke"),
  267           INFILE("infile", "<filename>", "input.file.name"),
  268           KEYALG("keyalg", "<keyalg>", "key.algorithm.name"),
  269           KEYPASS("keypass", "<arg>", "key.password"),
  270           KEYSIZE("keysize", "<keysize>", "key.bit.size"),
  271           KEYSTORE("keystore", "<keystore>", "keystore.name"),
  272           NEW("new", "<arg>", "new.password"),
  273           NOPROMPT("noprompt", null, "do.not.prompt"),
  274           OUTFILE("outfile", "<filename>", "output.file.name"),
  275           PROTECTED("protected", null, "password.through.protected.mechanism"),
  276           PROVIDERARG("providerarg", "<arg>", "provider.argument"),
  277           PROVIDERCLASS("providerclass", "<providerclass>", "provider.class.name"),
  278           PROVIDERNAME("providername", "<providername>", "provider.name"),
  279           PROVIDERPATH("providerpath", "<pathlist>", "provider.classpath"),
  280           RFC("rfc", null, "output.in.RFC.style"),
  281           SIGALG("sigalg", "<sigalg>", "signature.algorithm.name"),
  282           SRCALIAS("srcalias", "<srcalias>", "source.alias"),
  283           SRCKEYPASS("srckeypass", "<arg>", "source.key.password"),
  284           SRCKEYSTORE("srckeystore", "<srckeystore>", "source.keystore.name"),
  285           SRCPROTECTED("srcprotected", null, "source.keystore.password.protected"),
  286           SRCPROVIDERNAME("srcprovidername", "<srcprovidername>", "source.keystore.provider.name"),
  287           SRCSTOREPASS("srcstorepass", "<arg>", "source.keystore.password"),
  288           SRCSTORETYPE("srcstoretype", "<srcstoretype>", "source.keystore.type"),
  289           SSLSERVER("sslserver", "<server[:port]>", "SSL.server.host.and.port"),
  290           JARFILE("jarfile", "<filename>", "signed.jar.file"),
  291           STARTDATE("startdate", "<startdate>", "certificate.validity.start.date.time"),
  292           STOREPASS("storepass", "<arg>", "keystore.password"),
  293           STORETYPE("storetype", "<storetype>", "keystore.type"),
  294           TRUSTCACERTS("trustcacerts", null, "trust.certificates.from.cacerts"),
  295           V("v", null, "verbose.output"),
  296           VALIDITY("validity", "<valDays>", "validity.number.of.days");
  297   
  298           final String name, arg, description;
  299           Option(String name, String arg, String description) {
  300               this.name = name;
  301               this.arg = arg;
  302               this.description = description;
  303           }
  304           @Override
  305           public String toString() {
  306               return "-" + name;
  307           }
  308       };
  309   
  310       private static final Class[] PARAM_STRING = { String.class };
  311   
  312       private static final String JKS = "jks";
  313       private static final String NONE = "NONE";
  314       private static final String P11KEYSTORE = "PKCS11";
  315       private static final String P12KEYSTORE = "PKCS12";
  316       private final String keyAlias = "mykey";
  317   
  318       // for i18n
  319       private static final java.util.ResourceBundle rb =
  320           java.util.ResourceBundle.getBundle("sun.security.util.Resources");
  321       private static final Collator collator = Collator.getInstance();
  322       static {
  323           // this is for case insensitive string comparisons
  324           collator.setStrength(Collator.PRIMARY);
  325       };
  326   
  327       private KeyTool() { }
  328   
  329       public static void main(String[] args) throws Exception {
  330           KeyTool kt = new KeyTool();
  331           kt.run(args, System.out);
  332       }
  333   
  334       private void run(String[] args, PrintStream out) throws Exception {
  335           try {
  336               parseArgs(args);
  337               if (command != null) {
  338                   doCommands(out);
  339               }
  340           } catch (Exception e) {
  341               System.out.println(rb.getString("keytool.error.") + e);
  342               if (verbose) {
  343                   e.printStackTrace(System.out);
  344               }
  345               if (!debug) {
  346                   System.exit(1);
  347               } else {
  348                   throw e;
  349               }
  350           } finally {
  351               for (char[] pass : passwords) {
  352                   if (pass != null) {
  353                       Arrays.fill(pass, ' ');
  354                       pass = null;
  355                   }
  356               }
  357   
  358               if (ksStream != null) {
  359                   ksStream.close();
  360               }
  361           }
  362       }
  363   
  364       /**
  365        * Parse command line arguments.
  366        */
  367       void parseArgs(String[] args) {
  368   
  369           int i=0;
  370           boolean help = args.length == 0;
  371   
  372           for (i=0; (i < args.length) && args[i].startsWith("-"); i++) {
  373   
  374               String flags = args[i];
  375   
  376               // Check if the last option needs an arg
  377               if (i == args.length - 1) {
  378                   for (Option option: Option.values()) {
  379                       // Only options with an arg need to be checked
  380                       if (collator.compare(flags, option.toString()) == 0) {
  381                           if (option.arg != null) errorNeedArgument(flags);
  382                           break;
  383                       }
  384                   }
  385               }
  386   
  387               /*
  388                * Check modifiers
  389                */
  390               String modifier = null;
  391               int pos = flags.indexOf(':');
  392               if (pos > 0) {
  393                   modifier = flags.substring(pos+1);
  394                   flags = flags.substring(0, pos);
  395               }
  396               /*
  397                * command modes
  398                */
  399               boolean isCommand = false;
  400               for (Command c: Command.values()) {
  401                   if (collator.compare(flags, c.toString()) == 0) {
  402                       command = c;
  403                       isCommand = true;
  404                       break;
  405                   }
  406               }
  407   
  408               if (isCommand) {
  409                   // already recognized as a command
  410               } else if (collator.compare(flags, "-export") == 0) {
  411                   command = EXPORTCERT;
  412               } else if (collator.compare(flags, "-genkey") == 0) {
  413                   command = GENKEYPAIR;
  414               } else if (collator.compare(flags, "-import") == 0) {
  415                   command = IMPORTCERT;
  416               }
  417               /*
  418                * Help
  419                */
  420               else if (collator.compare(flags, "-help") == 0) {
  421                   help = true;
  422               }
  423   
  424               /*
  425                * specifiers
  426                */
  427               else if (collator.compare(flags, "-keystore") == 0 ||
  428                       collator.compare(flags, "-destkeystore") == 0) {
  429                   ksfname = args[++i];
  430               } else if (collator.compare(flags, "-storepass") == 0 ||
  431                       collator.compare(flags, "-deststorepass") == 0) {
  432                   storePass = getPass(modifier, args[++i]);
  433                   passwords.add(storePass);
  434               } else if (collator.compare(flags, "-storetype") == 0 ||
  435                       collator.compare(flags, "-deststoretype") == 0) {
  436                   storetype = args[++i];
  437               } else if (collator.compare(flags, "-srcstorepass") == 0) {
  438                   srcstorePass = getPass(modifier, args[++i]);
  439                   passwords.add(srcstorePass);
  440               } else if (collator.compare(flags, "-srcstoretype") == 0) {
  441                   srcstoretype = args[++i];
  442               } else if (collator.compare(flags, "-srckeypass") == 0) {
  443                   srckeyPass = getPass(modifier, args[++i]);
  444                   passwords.add(srckeyPass);
  445               } else if (collator.compare(flags, "-srcprovidername") == 0) {
  446                   srcProviderName = args[++i];
  447               } else if (collator.compare(flags, "-providername") == 0 ||
  448                       collator.compare(flags, "-destprovidername") == 0) {
  449                   providerName = args[++i];
  450               } else if (collator.compare(flags, "-providerpath") == 0) {
  451                   pathlist = args[++i];
  452               } else if (collator.compare(flags, "-keypass") == 0) {
  453                   keyPass = getPass(modifier, args[++i]);
  454                   passwords.add(keyPass);
  455               } else if (collator.compare(flags, "-new") == 0) {
  456                   newPass = getPass(modifier, args[++i]);
  457                   passwords.add(newPass);
  458               } else if (collator.compare(flags, "-destkeypass") == 0) {
  459                   destKeyPass = getPass(modifier, args[++i]);
  460                   passwords.add(destKeyPass);
  461               } else if (collator.compare(flags, "-alias") == 0 ||
  462                       collator.compare(flags, "-srcalias") == 0) {
  463                   alias = args[++i];
  464               } else if (collator.compare(flags, "-dest") == 0 ||
  465                       collator.compare(flags, "-destalias") == 0) {
  466                   dest = args[++i];
  467               } else if (collator.compare(flags, "-dname") == 0) {
  468                   dname = args[++i];
  469               } else if (collator.compare(flags, "-keysize") == 0) {
  470                   keysize = Integer.parseInt(args[++i]);
  471               } else if (collator.compare(flags, "-keyalg") == 0) {
  472                   keyAlgName = args[++i];
  473               } else if (collator.compare(flags, "-sigalg") == 0) {
  474                   sigAlgName = args[++i];
  475               } else if (collator.compare(flags, "-startdate") == 0) {
  476                   startDate = args[++i];
  477               } else if (collator.compare(flags, "-validity") == 0) {
  478                   validity = Long.parseLong(args[++i]);
  479               } else if (collator.compare(flags, "-ext") == 0) {
  480                   v3ext.add(args[++i]);
  481               } else if (collator.compare(flags, "-id") == 0) {
  482                   ids.add(args[++i]);
  483               } else if (collator.compare(flags, "-file") == 0) {
  484                   filename = args[++i];
  485               } else if (collator.compare(flags, "-infile") == 0) {
  486                   infilename = args[++i];
  487               } else if (collator.compare(flags, "-outfile") == 0) {
  488                   outfilename = args[++i];
  489               } else if (collator.compare(flags, "-sslserver") == 0) {
  490                   sslserver = args[++i];
  491               } else if (collator.compare(flags, "-jarfile") == 0) {
  492                   jarfile = args[++i];
  493               } else if (collator.compare(flags, "-srckeystore") == 0) {
  494                   srcksfname = args[++i];
  495               } else if ((collator.compare(flags, "-provider") == 0) ||
  496                           (collator.compare(flags, "-providerclass") == 0)) {
  497                   if (providers == null) {
  498                       providers = new HashSet<Pair <String, String>> (3);
  499                   }
  500                   String providerClass = args[++i];
  501                   String providerArg = null;
  502   
  503                   if (args.length > (i+1)) {
  504                       flags = args[i+1];
  505                       if (collator.compare(flags, "-providerarg") == 0) {
  506                           if (args.length == (i+2)) errorNeedArgument(flags);
  507                           providerArg = args[i+2];
  508                           i += 2;
  509                       }
  510                   }
  511                   providers.add(
  512                           Pair.of(providerClass, providerArg));
  513               }
  514   
  515               /*
  516                * options
  517                */
  518               else if (collator.compare(flags, "-v") == 0) {
  519                   verbose = true;
  520               } else if (collator.compare(flags, "-debug") == 0) {
  521                   debug = true;
  522               } else if (collator.compare(flags, "-rfc") == 0) {
  523                   rfc = true;
  524               } else if (collator.compare(flags, "-noprompt") == 0) {
  525                   noprompt = true;
  526               } else if (collator.compare(flags, "-trustcacerts") == 0) {
  527                   trustcacerts = true;
  528               } else if (collator.compare(flags, "-protected") == 0 ||
  529                       collator.compare(flags, "-destprotected") == 0) {
  530                   protectedPath = true;
  531               } else if (collator.compare(flags, "-srcprotected") == 0) {
  532                   srcprotectedPath = true;
  533               } else  {
  534                   System.err.println(rb.getString("Illegal.option.") + flags);
  535                   tinyHelp();
  536               }
  537           }
  538   
  539           if (i<args.length) {
  540               System.err.println(rb.getString("Illegal.option.") + args[i]);
  541               tinyHelp();
  542           }
  543   
  544           if (command == null) {
  545               if (help) {
  546                   usage();
  547               } else {
  548                   System.err.println(rb.getString("Usage.error.no.command.provided"));
  549                   tinyHelp();
  550               }
  551           } else if (help) {
  552               usage();
  553               command = null;
  554           }
  555       }
  556   
  557       boolean isKeyStoreRelated(Command cmd) {
  558           return cmd != PRINTCERT && cmd != PRINTCERTREQ;
  559       }
  560   
  561       /**
  562        * Execute the commands.
  563        */
  564       void doCommands(PrintStream out) throws Exception {
  565   
  566           if (storetype == null) {
  567               storetype = KeyStore.getDefaultType();
  568           }
  569           storetype = KeyStoreUtil.niceStoreTypeName(storetype);
  570   
  571           if (srcstoretype == null) {
  572               srcstoretype = KeyStore.getDefaultType();
  573           }
  574           srcstoretype = KeyStoreUtil.niceStoreTypeName(srcstoretype);
  575   
  576           if (P11KEYSTORE.equalsIgnoreCase(storetype) ||
  577                   KeyStoreUtil.isWindowsKeyStore(storetype)) {
  578               token = true;
  579               if (ksfname == null) {
  580                   ksfname = NONE;
  581               }
  582           }
  583           if (NONE.equals(ksfname)) {
  584               nullStream = true;
  585           }
  586   
  587           if (token && !nullStream) {
  588               System.err.println(MessageFormat.format(rb.getString
  589                   (".keystore.must.be.NONE.if.storetype.is.{0}"), storetype));
  590               System.err.println();
  591               tinyHelp();
  592           }
  593   
  594           if (token &&
  595               (command == KEYPASSWD || command == STOREPASSWD)) {
  596               throw new UnsupportedOperationException(MessageFormat.format(rb.getString
  597                           (".storepasswd.and.keypasswd.commands.not.supported.if.storetype.is.{0}"), storetype));
  598           }
  599   
  600           if (P12KEYSTORE.equalsIgnoreCase(storetype) && command == KEYPASSWD) {
  601               throw new UnsupportedOperationException(rb.getString
  602                           (".keypasswd.commands.not.supported.if.storetype.is.PKCS12"));
  603           }
  604   
  605           if (token && (keyPass != null || newPass != null || destKeyPass != null)) {
  606               throw new IllegalArgumentException(MessageFormat.format(rb.getString
  607                   (".keypass.and.new.can.not.be.specified.if.storetype.is.{0}"), storetype));
  608           }
  609   
  610           if (protectedPath) {
  611               if (storePass != null || keyPass != null ||
  612                       newPass != null || destKeyPass != null) {
  613                   throw new IllegalArgumentException(rb.getString
  614                           ("if.protected.is.specified.then.storepass.keypass.and.new.must.not.be.specified"));
  615               }
  616           }
  617   
  618           if (srcprotectedPath) {
  619               if (srcstorePass != null || srckeyPass != null) {
  620                   throw new IllegalArgumentException(rb.getString
  621                           ("if.srcprotected.is.specified.then.srcstorepass.and.srckeypass.must.not.be.specified"));
  622               }
  623           }
  624   
  625           if (KeyStoreUtil.isWindowsKeyStore(storetype)) {
  626               if (storePass != null || keyPass != null ||
  627                       newPass != null || destKeyPass != null) {
  628                   throw new IllegalArgumentException(rb.getString
  629                           ("if.keystore.is.not.password.protected.then.storepass.keypass.and.new.must.not.be.specified"));
  630               }
  631           }
  632   
  633           if (KeyStoreUtil.isWindowsKeyStore(srcstoretype)) {
  634               if (srcstorePass != null || srckeyPass != null) {
  635                   throw new IllegalArgumentException(rb.getString
  636                           ("if.source.keystore.is.not.password.protected.then.srcstorepass.and.srckeypass.must.not.be.specified"));
  637               }
  638           }
  639   
  640           if (validity <= (long)0) {
  641               throw new Exception
  642                   (rb.getString("Validity.must.be.greater.than.zero"));
  643           }
  644   
  645           // Try to load and install specified provider
  646           if (providers != null) {
  647               ClassLoader cl = null;
  648               if (pathlist != null) {
  649                   String path = null;
  650                   path = PathList.appendPath(
  651                           path, System.getProperty("java.class.path"));
  652                   path = PathList.appendPath(
  653                           path, System.getProperty("env.class.path"));
  654                   path = PathList.appendPath(path, pathlist);
  655   
  656                   URL[] urls = PathList.pathToURLs(path);
  657                   cl = new URLClassLoader(urls);
  658               } else {
  659                   cl = ClassLoader.getSystemClassLoader();
  660               }
  661   
  662               for (Pair <String, String> provider: providers) {
  663                   String provName = provider.fst;
  664                   Class<?> provClass;
  665                   if (cl != null) {
  666                       provClass = cl.loadClass(provName);
  667                   } else {
  668                       provClass = Class.forName(provName);
  669                   }
  670   
  671                   String provArg = provider.snd;
  672                   Object obj;
  673                   if (provArg == null) {
  674                       obj = provClass.newInstance();
  675                   } else {
  676                       Constructor<?> c = provClass.getConstructor(PARAM_STRING);
  677                       obj = c.newInstance(provArg);
  678                   }
  679                   if (!(obj instanceof Provider)) {
  680                       MessageFormat form = new MessageFormat
  681                           (rb.getString("provName.not.a.provider"));
  682                       Object[] source = {provName};
  683                       throw new Exception(form.format(source));
  684                   }
  685                   Security.addProvider((Provider)obj);
  686               }
  687           }
  688   
  689           if (command == LIST && verbose && rfc) {
  690               System.err.println(rb.getString
  691                   ("Must.not.specify.both.v.and.rfc.with.list.command"));
  692               tinyHelp();
  693           }
  694   
  695           // Make sure provided passwords are at least 6 characters long
  696           if (command == GENKEYPAIR && keyPass!=null && keyPass.length < 6) {
  697               throw new Exception(rb.getString
  698                   ("Key.password.must.be.at.least.6.characters"));
  699           }
  700           if (newPass != null && newPass.length < 6) {
  701               throw new Exception(rb.getString
  702                   ("New.password.must.be.at.least.6.characters"));
  703           }
  704           if (destKeyPass != null && destKeyPass.length < 6) {
  705               throw new Exception(rb.getString
  706                   ("New.password.must.be.at.least.6.characters"));
  707           }
  708   
  709           // Check if keystore exists.
  710           // If no keystore has been specified at the command line, try to use
  711           // the default, which is located in $HOME/.keystore.
  712           // If the command is "genkey", "identitydb", "import", or "printcert",
  713           // it is OK not to have a keystore.
  714           if (isKeyStoreRelated(command)) {
  715               if (ksfname == null) {
  716                   ksfname = System.getProperty("user.home") + File.separator
  717                       + ".keystore";
  718               }
  719   
  720               if (!nullStream) {
  721                   try {
  722                       ksfile = new File(ksfname);
  723                       // Check if keystore file is empty
  724                       if (ksfile.exists() && ksfile.length() == 0) {
  725                           throw new Exception(rb.getString
  726                           ("Keystore.file.exists.but.is.empty.") + ksfname);
  727                       }
  728                       ksStream = new FileInputStream(ksfile);
  729                   } catch (FileNotFoundException e) {
  730                       if (command != GENKEYPAIR &&
  731                           command != GENSECKEY &&
  732                           command != IDENTITYDB &&
  733                           command != IMPORTCERT &&
  734                           command != IMPORTKEYSTORE &&
  735                           command != PRINTCRL) {
  736                           throw new Exception(rb.getString
  737                                   ("Keystore.file.does.not.exist.") + ksfname);
  738                       }
  739                   }
  740               }
  741           }
  742   
  743           if ((command == KEYCLONE || command == CHANGEALIAS)
  744                   && dest == null) {
  745               dest = getAlias("destination");
  746               if ("".equals(dest)) {
  747                   throw new Exception(rb.getString
  748                           ("Must.specify.destination.alias"));
  749               }
  750           }
  751   
  752           if (command == DELETE && alias == null) {
  753               alias = getAlias(null);
  754               if ("".equals(alias)) {
  755                   throw new Exception(rb.getString("Must.specify.alias"));
  756               }
  757           }
  758   
  759           // Create new keystore
  760           if (providerName == null) {
  761               keyStore = KeyStore.getInstance(storetype);
  762           } else {
  763               keyStore = KeyStore.getInstance(storetype, providerName);
  764           }
  765   
  766           /*
  767            * Load the keystore data.
  768            *
  769            * At this point, it's OK if no keystore password has been provided.
  770            * We want to make sure that we can load the keystore data, i.e.,
  771            * the keystore data has the right format. If we cannot load the
  772            * keystore, why bother asking the user for his or her password?
  773            * Only if we were able to load the keystore, and no keystore
  774            * password has been provided, will we prompt the user for the
  775            * keystore password to verify the keystore integrity.
  776            * This means that the keystore is loaded twice: first load operation
  777            * checks the keystore format, second load operation verifies the
  778            * keystore integrity.
  779            *
  780            * If the keystore password has already been provided (at the
  781            * command line), however, the keystore is loaded only once, and the
  782            * keystore format and integrity are checked "at the same time".
  783            *
  784            * Null stream keystores are loaded later.
  785            */
  786           if (!nullStream) {
  787               keyStore.load(ksStream, storePass);
  788               if (ksStream != null) {
  789                   ksStream.close();
  790               }
  791           }
  792   
  793           // All commands that create or modify the keystore require a keystore
  794           // password.
  795   
  796           if (nullStream && storePass != null) {
  797               keyStore.load(null, storePass);
  798           } else if (!nullStream && storePass != null) {
  799               // If we are creating a new non nullStream-based keystore,
  800               // insist that the password be at least 6 characters
  801               if (ksStream == null && storePass.length < 6) {
  802                   throw new Exception(rb.getString
  803                           ("Keystore.password.must.be.at.least.6.characters"));
  804               }
  805           } else if (storePass == null) {
  806   
  807               // only prompt if (protectedPath == false)
  808   
  809               if (!protectedPath && !KeyStoreUtil.isWindowsKeyStore(storetype) &&
  810                   (command == CERTREQ ||
  811                           command == DELETE ||
  812                           command == GENKEYPAIR ||
  813                           command == GENSECKEY ||
  814                           command == IMPORTCERT ||
  815                           command == IMPORTKEYSTORE ||
  816                           command == KEYCLONE ||
  817                           command == CHANGEALIAS ||
  818                           command == SELFCERT ||
  819                           command == STOREPASSWD ||
  820                           command == KEYPASSWD ||
  821                           command == IDENTITYDB)) {
  822                   int count = 0;
  823                   do {
  824                       if (command == IMPORTKEYSTORE) {
  825                           System.err.print
  826                                   (rb.getString("Enter.destination.keystore.password."));
  827                       } else {
  828                           System.err.print
  829                                   (rb.getString("Enter.keystore.password."));
  830                       }
  831                       System.err.flush();
  832                       storePass = Password.readPassword(System.in);
  833                       passwords.add(storePass);
  834   
  835                       // If we are creating a new non nullStream-based keystore,
  836                       // insist that the password be at least 6 characters
  837                       if (!nullStream && (storePass == null || storePass.length < 6)) {
  838                           System.err.println(rb.getString
  839                                   ("Keystore.password.is.too.short.must.be.at.least.6.characters"));
  840                           storePass = null;
  841                       }
  842   
  843                       // If the keystore file does not exist and needs to be
  844                       // created, the storepass should be prompted twice.
  845                       if (storePass != null && !nullStream && ksStream == null) {
  846                           System.err.print(rb.getString("Re.enter.new.password."));
  847                           char[] storePassAgain = Password.readPassword(System.in);
  848                           passwords.add(storePassAgain);
  849                           if (!Arrays.equals(storePass, storePassAgain)) {
  850                               System.err.println
  851                                   (rb.getString("They.don.t.match.Try.again"));
  852                               storePass = null;
  853                           }
  854                       }
  855   
  856                       count++;
  857                   } while ((storePass == null) && count < 3);
  858   
  859   
  860                   if (storePass == null) {
  861                       System.err.println
  862                           (rb.getString("Too.many.failures.try.later"));
  863                       return;
  864                   }
  865               } else if (!protectedPath
  866                       && !KeyStoreUtil.isWindowsKeyStore(storetype)
  867                       && isKeyStoreRelated(command)) {
  868                   // here we have EXPORTCERT and LIST (info valid until STOREPASSWD)
  869                   if (command != PRINTCRL) {
  870                       System.err.print(rb.getString("Enter.keystore.password."));
  871                       System.err.flush();
  872                       storePass = Password.readPassword(System.in);
  873                       passwords.add(storePass);
  874                   }
  875               }
  876   
  877               // Now load a nullStream-based keystore,
  878               // or verify the integrity of an input stream-based keystore
  879               if (nullStream) {
  880                   keyStore.load(null, storePass);
  881               } else if (ksStream != null) {
  882                   ksStream = new FileInputStream(ksfile);
  883                   keyStore.load(ksStream, storePass);
  884                   ksStream.close();
  885               }
  886           }
  887   
  888           if (storePass != null && P12KEYSTORE.equalsIgnoreCase(storetype)) {
  889               MessageFormat form = new MessageFormat(rb.getString(
  890                   "Warning.Different.store.and.key.passwords.not.supported.for.PKCS12.KeyStores.Ignoring.user.specified.command.value."));
  891               if (keyPass != null && !Arrays.equals(storePass, keyPass)) {
  892                   Object[] source = {"-keypass"};
  893                   System.err.println(form.format(source));
  894                   keyPass = storePass;
  895               }
  896               if (newPass != null && !Arrays.equals(storePass, newPass)) {
  897                   Object[] source = {"-new"};
  898                   System.err.println(form.format(source));
  899                   newPass = storePass;
  900               }
  901               if (destKeyPass != null && !Arrays.equals(storePass, destKeyPass)) {
  902                   Object[] source = {"-destkeypass"};
  903                   System.err.println(form.format(source));
  904                   destKeyPass = storePass;
  905               }
  906           }
  907   
  908           // Create a certificate factory
  909           if (command == PRINTCERT || command == IMPORTCERT
  910                   || command == IDENTITYDB || command == PRINTCRL) {
  911               cf = CertificateFactory.getInstance("X509");
  912           }
  913   
  914           if (trustcacerts) {
  915               caks = getCacertsKeyStore();
  916           }
  917   
  918           // Perform the specified command
  919           if (command == CERTREQ) {
  920               PrintStream ps = null;
  921               if (filename != null) {
  922                   ps = new PrintStream(new FileOutputStream
  923                                                    (filename));
  924                   out = ps;
  925               }
  926               try {
  927                   doCertReq(alias, sigAlgName, out);
  928               } finally {
  929                   if (ps != null) {
  930                       ps.close();
  931                   }
  932               }
  933               if (verbose && filename != null) {
  934                   MessageFormat form = new MessageFormat(rb.getString
  935                           ("Certification.request.stored.in.file.filename."));
  936                   Object[] source = {filename};
  937                   System.err.println(form.format(source));
  938                   System.err.println(rb.getString("Submit.this.to.your.CA"));
  939               }
  940           } else if (command == DELETE) {
  941               doDeleteEntry(alias);
  942               kssave = true;
  943           } else if (command == EXPORTCERT) {
  944               PrintStream ps = null;
  945               if (filename != null) {
  946                   ps = new PrintStream(new FileOutputStream
  947                                                    (filename));
  948                   out = ps;
  949               }
  950               try {
  951                   doExportCert(alias, out);
  952               } finally {
  953                   if (ps != null) {
  954                       ps.close();
  955                   }
  956               }
  957               if (filename != null) {
  958                   MessageFormat form = new MessageFormat(rb.getString
  959                           ("Certificate.stored.in.file.filename."));
  960                   Object[] source = {filename};
  961                   System.err.println(form.format(source));
  962               }
  963           } else if (command == GENKEYPAIR) {
  964               if (keyAlgName == null) {
  965                   keyAlgName = "DSA";
  966               }
  967               doGenKeyPair(alias, dname, keyAlgName, keysize, sigAlgName);
  968               kssave = true;
  969           } else if (command == GENSECKEY) {
  970               if (keyAlgName == null) {
  971                   keyAlgName = "DES";
  972               }
  973               doGenSecretKey(alias, keyAlgName, keysize);
  974               kssave = true;
  975           } else if (command == IDENTITYDB) {
  976               InputStream inStream = System.in;
  977               if (filename != null) {
  978                   inStream = new FileInputStream(filename);
  979               }
  980               try {
  981                   doImportIdentityDatabase(inStream);
  982               } finally {
  983                   if (inStream != System.in) {
  984                       inStream.close();
  985                   }
  986               }
  987           } else if (command == IMPORTCERT) {
  988               InputStream inStream = System.in;
  989               if (filename != null) {
  990                   inStream = new FileInputStream(filename);
  991               }
  992               String importAlias = (alias!=null)?alias:keyAlias;
  993               try {
  994                   if (keyStore.entryInstanceOf(
  995                           importAlias, KeyStore.PrivateKeyEntry.class)) {
  996                       kssave = installReply(importAlias, inStream);
  997                       if (kssave) {
  998                           System.err.println(rb.getString
  999                               ("Certificate.reply.was.installed.in.keystore"));
 1000                       } else {
 1001                           System.err.println(rb.getString
 1002                               ("Certificate.reply.was.not.installed.in.keystore"));
 1003                       }
 1004                   } else if (!keyStore.containsAlias(importAlias) ||
 1005                           keyStore.entryInstanceOf(importAlias,
 1006                               KeyStore.TrustedCertificateEntry.class)) {
 1007                       kssave = addTrustedCert(importAlias, inStream);
 1008                       if (kssave) {
 1009                           System.err.println(rb.getString
 1010                               ("Certificate.was.added.to.keystore"));
 1011                       } else {
 1012                           System.err.println(rb.getString
 1013                               ("Certificate.was.not.added.to.keystore"));
 1014                       }
 1015                   }
 1016               } finally {
 1017                   if (inStream != System.in) {
 1018                       inStream.close();
 1019                   }
 1020               }
 1021           } else if (command == IMPORTKEYSTORE) {
 1022               doImportKeyStore();
 1023               kssave = true;
 1024           } else if (command == KEYCLONE) {
 1025               keyPassNew = newPass;
 1026   
 1027               // added to make sure only key can go thru
 1028               if (alias == null) {
 1029                   alias = keyAlias;
 1030               }
 1031               if (keyStore.containsAlias(alias) == false) {
 1032                   MessageFormat form = new MessageFormat
 1033                       (rb.getString("Alias.alias.does.not.exist"));
 1034                   Object[] source = {alias};
 1035                   throw new Exception(form.format(source));
 1036               }
 1037               if (!keyStore.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) {
 1038                   MessageFormat form = new MessageFormat(rb.getString(
 1039                           "Alias.alias.references.an.entry.type.that.is.not.a.private.key.entry.The.keyclone.command.only.supports.cloning.of.private.key"));
 1040                   Object[] source = {alias};
 1041                   throw new Exception(form.format(source));
 1042               }
 1043   
 1044               doCloneEntry(alias, dest, true);  // Now everything can be cloned
 1045               kssave = true;
 1046           } else if (command == CHANGEALIAS) {
 1047               if (alias == null) {
 1048                   alias = keyAlias;
 1049               }
 1050               doCloneEntry(alias, dest, false);
 1051               // in PKCS11, clone a PrivateKeyEntry will delete the old one
 1052               if (keyStore.containsAlias(alias)) {
 1053                   doDeleteEntry(alias);
 1054               }
 1055               kssave = true;
 1056           } else if (command == KEYPASSWD) {
 1057               keyPassNew = newPass;
 1058               doChangeKeyPasswd(alias);
 1059               kssave = true;
 1060           } else if (command == LIST) {
 1061               if (alias != null) {
 1062                   doPrintEntry(alias, out, true);
 1063               } else {
 1064                   doPrintEntries(out);
 1065               }
 1066           } else if (command == PRINTCERT) {
 1067               doPrintCert(out);
 1068           } else if (command == SELFCERT) {
 1069               doSelfCert(alias, dname, sigAlgName);
 1070               kssave = true;
 1071           } else if (command == STOREPASSWD) {
 1072               storePassNew = newPass;
 1073               if (storePassNew == null) {
 1074                   storePassNew = getNewPasswd("keystore password", storePass);
 1075               }
 1076               kssave = true;
 1077           } else if (command == GENCERT) {
 1078               if (alias == null) {
 1079                   alias = keyAlias;
 1080               }
 1081               InputStream inStream = System.in;
 1082               if (infilename != null) {
 1083                   inStream = new FileInputStream(infilename);
 1084               }
 1085               PrintStream ps = null;
 1086               if (outfilename != null) {
 1087                   ps = new PrintStream(new FileOutputStream(outfilename));
 1088                   out = ps;
 1089               }
 1090               try {
 1091                   doGenCert(alias, sigAlgName, inStream, out);
 1092               } finally {
 1093                   if (inStream != System.in) {
 1094                       inStream.close();
 1095                   }
 1096                   if (ps != null) {
 1097                       ps.close();
 1098                   }
 1099               }
 1100           } else if (command == GENCRL) {
 1101               if (alias == null) {
 1102                   alias = keyAlias;
 1103               }
 1104               PrintStream ps = null;
 1105               if (filename != null) {
 1106                   ps = new PrintStream(new FileOutputStream(filename));
 1107                   out = ps;
 1108               }
 1109               try {
 1110                   doGenCRL(out);
 1111               } finally {
 1112                   if (ps != null) {
 1113                       ps.close();
 1114                   }
 1115               }
 1116           } else if (command == PRINTCERTREQ) {
 1117               InputStream inStream = System.in;
 1118               if (filename != null) {
 1119                   inStream = new FileInputStream(filename);
 1120               }
 1121               try {
 1122                   doPrintCertReq(inStream, out);
 1123               } finally {
 1124                   if (inStream != System.in) {
 1125                       inStream.close();
 1126                   }
 1127               }
 1128           } else if (command == PRINTCRL) {
 1129               doPrintCRL(filename, out);
 1130           }
 1131   
 1132           // If we need to save the keystore, do so.
 1133           if (kssave) {
 1134               if (verbose) {
 1135                   MessageFormat form = new MessageFormat
 1136                           (rb.getString(".Storing.ksfname."));
 1137                   Object[] source = {nullStream ? "keystore" : ksfname};
 1138                   System.err.println(form.format(source));
 1139               }
 1140   
 1141               if (token) {
 1142                   keyStore.store(null, null);
 1143               } else {
 1144                   FileOutputStream fout = null;
 1145                   try {
 1146                       fout = (nullStream ?
 1147                                           (FileOutputStream)null :
 1148                                           new FileOutputStream(ksfname));
 1149                       keyStore.store
 1150                           (fout,
 1151                           (storePassNew!=null) ? storePassNew : storePass);
 1152                   } finally {
 1153                       if (fout != null) {
 1154                           fout.close();
 1155                       }
 1156                   }
 1157               }
 1158           }
 1159       }
 1160   
 1161       /**
 1162        * Generate a certificate: Read PKCS10 request from in, and print
 1163        * certificate to out. Use alias as CA, sigAlgName as the signature
 1164        * type.
 1165        */
 1166       private void doGenCert(String alias, String sigAlgName, InputStream in, PrintStream out)
 1167               throws Exception {
 1168   
 1169   
 1170           Certificate signerCert = keyStore.getCertificate(alias);
 1171           byte[] encoded = signerCert.getEncoded();
 1172           X509CertImpl signerCertImpl = new X509CertImpl(encoded);
 1173           X509CertInfo signerCertInfo = (X509CertInfo)signerCertImpl.get(
 1174                   X509CertImpl.NAME + "." + X509CertImpl.INFO);
 1175           X500Name issuer = (X500Name)signerCertInfo.get(X509CertInfo.SUBJECT + "." +
 1176                                              CertificateSubjectName.DN_NAME);
 1177   
 1178           Date firstDate = getStartDate(startDate);
 1179           Date lastDate = new Date();
 1180           lastDate.setTime(firstDate.getTime() + validity*1000L*24L*60L*60L);
 1181           CertificateValidity interval = new CertificateValidity(firstDate,
 1182                                                                  lastDate);
 1183   
 1184           PrivateKey privateKey =
 1185                   (PrivateKey)recoverKey(alias, storePass, keyPass).fst;
 1186           if (sigAlgName == null) {
 1187               sigAlgName = getCompatibleSigAlgName(privateKey.getAlgorithm());
 1188           }
 1189           Signature signature = Signature.getInstance(sigAlgName);
 1190           signature.initSign(privateKey);
 1191   
 1192           X509CertInfo info = new X509CertInfo();
 1193           info.set(X509CertInfo.VALIDITY, interval);
 1194           info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(
 1195                       new java.util.Random().nextInt() & 0x7fffffff));
 1196           info.set(X509CertInfo.VERSION,
 1197                       new CertificateVersion(CertificateVersion.V3));
 1198           info.set(X509CertInfo.ALGORITHM_ID,
 1199                       new CertificateAlgorithmId(
 1200                           AlgorithmId.getAlgorithmId(sigAlgName)));
 1201           info.set(X509CertInfo.ISSUER, new CertificateIssuerName(issuer));
 1202   
 1203           BufferedReader reader = new BufferedReader(new InputStreamReader(in));
 1204           boolean canRead = false;
 1205           StringBuffer sb = new StringBuffer();
 1206           while (true) {
 1207               String s = reader.readLine();
 1208               if (s == null) break;
 1209               // OpenSSL does not use NEW
 1210               //if (s.startsWith("-----BEGIN NEW CERTIFICATE REQUEST-----")) {
 1211               if (s.startsWith("-----BEGIN") && s.indexOf("REQUEST") >= 0) {
 1212                   canRead = true;
 1213               //} else if (s.startsWith("-----END NEW CERTIFICATE REQUEST-----")) {
 1214               } else if (s.startsWith("-----END") && s.indexOf("REQUEST") >= 0) {
 1215                   break;
 1216               } else if (canRead) {
 1217                   sb.append(s);
 1218               }
 1219           }
 1220           byte[] rawReq = new BASE64Decoder().decodeBuffer(new String(sb));
 1221           PKCS10 req = new PKCS10(rawReq);
 1222   
 1223           info.set(X509CertInfo.KEY, new CertificateX509Key(req.getSubjectPublicKeyInfo()));
 1224           info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(
 1225                   dname==null?req.getSubjectName():new X500Name(dname)));
 1226           CertificateExtensions reqex = null;
 1227           Iterator<PKCS10Attribute> attrs = req.getAttributes().getAttributes().iterator();
 1228           while (attrs.hasNext()) {
 1229               PKCS10Attribute attr = attrs.next();
 1230               if (attr.getAttributeId().equals(PKCS9Attribute.EXTENSION_REQUEST_OID)) {
 1231                   reqex = (CertificateExtensions)attr.getAttributeValue();
 1232               }
 1233           }
 1234           CertificateExtensions ext = createV3Extensions(
 1235                   reqex,
 1236                   null,
 1237                   v3ext,
 1238                   req.getSubjectPublicKeyInfo(),
 1239                   signerCert.getPublicKey());
 1240           info.set(X509CertInfo.EXTENSIONS, ext);
 1241           X509CertImpl cert = new X509CertImpl(info);
 1242           cert.sign(privateKey, sigAlgName);
 1243           dumpCert(cert, out);
 1244           for (Certificate ca: keyStore.getCertificateChain(alias)) {
 1245               if (ca instanceof X509Certificate) {
 1246                   X509Certificate xca = (X509Certificate)ca;
 1247                   if (!isSelfSigned(xca)) {
 1248                       dumpCert(xca, out);
 1249                   }
 1250               }
 1251           }
 1252       }
 1253   
 1254       private void doGenCRL(PrintStream out)
 1255               throws Exception {
 1256           if (ids == null) {
 1257               throw new Exception("Must provide -id when -gencrl");
 1258           }
 1259           Certificate signerCert = keyStore.getCertificate(alias);
 1260           byte[] encoded = signerCert.getEncoded();
 1261           X509CertImpl signerCertImpl = new X509CertImpl(encoded);
 1262           X509CertInfo signerCertInfo = (X509CertInfo)signerCertImpl.get(
 1263                   X509CertImpl.NAME + "." + X509CertImpl.INFO);
 1264           X500Name owner = (X500Name)signerCertInfo.get(X509CertInfo.SUBJECT + "." +
 1265                                              CertificateSubjectName.DN_NAME);
 1266   
 1267           Date firstDate = getStartDate(startDate);
 1268           Date lastDate = (Date) firstDate.clone();
 1269           lastDate.setTime(lastDate.getTime() + (long)validity*1000*24*60*60);
 1270           CertificateValidity interval = new CertificateValidity(firstDate,
 1271                                                                  lastDate);
 1272   
 1273   
 1274           PrivateKey privateKey =
 1275                   (PrivateKey)recoverKey(alias, storePass, keyPass).fst;
 1276           if (sigAlgName == null) {
 1277               sigAlgName = getCompatibleSigAlgName(privateKey.getAlgorithm());
 1278           }
 1279   
 1280           X509CRLEntry[] badCerts = new X509CRLEntry[ids.size()];
 1281           for (int i=0; i<ids.size(); i++) {
 1282               String id = ids.get(i);
 1283               int d = id.indexOf(':');
 1284               if (d >= 0) {
 1285                   CRLExtensions ext = new CRLExtensions();
 1286                   ext.set("Reason", new CRLReasonCodeExtension(Integer.parseInt(id.substring(d+1))));
 1287                   badCerts[i] = new X509CRLEntryImpl(new BigInteger(id.substring(0, d)),
 1288                           firstDate, ext);
 1289               } else {
 1290                   badCerts[i] = new X509CRLEntryImpl(new BigInteger(ids.get(i)), firstDate);
 1291               }
 1292           }
 1293           X509CRLImpl crl = new X509CRLImpl(owner, firstDate, lastDate, badCerts);
 1294           crl.sign(privateKey, sigAlgName);
 1295           if (rfc) {
 1296               out.println("-----BEGIN X509 CRL-----");
 1297               new BASE64Encoder().encodeBuffer(crl.getEncodedInternal(), out);
 1298               out.println("-----END X509 CRL-----");
 1299           } else {
 1300               out.write(crl.getEncodedInternal());
 1301           }
 1302       }
 1303   
 1304       /**
 1305        * Creates a PKCS#10 cert signing request, corresponding to the
 1306        * keys (and name) associated with a given alias.
 1307        */
 1308       private void doCertReq(String alias, String sigAlgName, PrintStream out)
 1309           throws Exception
 1310       {
 1311           if (alias == null) {
 1312               alias = keyAlias;
 1313           }
 1314   
 1315           Pair<Key,char[]> objs = recoverKey(alias, storePass, keyPass);
 1316           PrivateKey privKey = (PrivateKey)objs.fst;
 1317           if (keyPass == null) {
 1318               keyPass = objs.snd;
 1319           }
 1320   
 1321           Certificate cert = keyStore.getCertificate(alias);
 1322           if (cert == null) {
 1323               MessageFormat form = new MessageFormat
 1324                   (rb.getString("alias.has.no.public.key.certificate."));
 1325               Object[] source = {alias};
 1326               throw new Exception(form.format(source));
 1327           }
 1328           PKCS10 request = new PKCS10(cert.getPublicKey());
 1329           CertificateExtensions ext = createV3Extensions(null, null, v3ext, cert.getPublicKey(), null);
 1330           // Attribute name is not significant
 1331           request.getAttributes().setAttribute(X509CertInfo.EXTENSIONS,
 1332                   new PKCS10Attribute(PKCS9Attribute.EXTENSION_REQUEST_OID, ext));
 1333   
 1334           // Construct a Signature object, so that we can sign the request
 1335           if (sigAlgName == null) {
 1336               sigAlgName = getCompatibleSigAlgName(privKey.getAlgorithm());
 1337           }
 1338   
 1339           Signature signature = Signature.getInstance(sigAlgName);
 1340           signature.initSign(privKey);
 1341           X500Name subject = dname == null?
 1342                   new X500Name(((X509Certificate)cert).getSubjectDN().toString()):
 1343                   new X500Name(dname);
 1344   
 1345           // Sign the request and base-64 encode it
 1346           request.encodeAndSign(subject, signature);
 1347           request.print(out);
 1348       }
 1349   
 1350       /**
 1351        * Deletes an entry from the keystore.
 1352        */
 1353       private void doDeleteEntry(String alias) throws Exception {
 1354           if (keyStore.containsAlias(alias) == false) {
 1355               MessageFormat form = new MessageFormat
 1356                   (rb.getString("Alias.alias.does.not.exist"));
 1357               Object[] source = {alias};
 1358               throw new Exception(form.format(source));
 1359           }
 1360           keyStore.deleteEntry(alias);
 1361       }
 1362   
 1363       /**
 1364        * Exports a certificate from the keystore.
 1365        */
 1366       private void doExportCert(String alias, PrintStream out)
 1367           throws Exception
 1368       {
 1369           if (storePass == null
 1370                   && !KeyStoreUtil.isWindowsKeyStore(storetype)) {
 1371               printWarning();
 1372           }
 1373           if (alias == null) {
 1374               alias = keyAlias;
 1375           }
 1376           if (keyStore.containsAlias(alias) == false) {
 1377               MessageFormat form = new MessageFormat
 1378                   (rb.getString("Alias.alias.does.not.exist"));
 1379               Object[] source = {alias};
 1380               throw new Exception(form.format(source));
 1381           }
 1382   
 1383           X509Certificate cert = (X509Certificate)keyStore.getCertificate(alias);
 1384           if (cert == null) {
 1385               MessageFormat form = new MessageFormat
 1386                   (rb.getString("Alias.alias.has.no.certificate"));
 1387               Object[] source = {alias};
 1388               throw new Exception(form.format(source));
 1389           }
 1390           dumpCert(cert, out);
 1391       }
 1392   
 1393       /**
 1394        * Prompt the user for a keypass when generating a key entry.
 1395        * @param alias the entry we will set password for
 1396        * @param orig the original entry of doing a dup, null if generate new
 1397        * @param origPass the password to copy from if user press ENTER
 1398        */
 1399       private char[] promptForKeyPass(String alias, String orig, char[] origPass) throws Exception{
 1400           if (P12KEYSTORE.equalsIgnoreCase(storetype)) {
 1401               return origPass;
 1402           } else if (!token) {
 1403               // Prompt for key password
 1404               int count;
 1405               for (count = 0; count < 3; count++) {
 1406                   MessageFormat form = new MessageFormat(rb.getString
 1407                           ("Enter.key.password.for.alias."));
 1408                   Object[] source = {alias};
 1409                   System.err.println(form.format(source));
 1410                   if (orig == null) {
 1411                       System.err.print(rb.getString
 1412                               (".RETURN.if.same.as.keystore.password."));
 1413                   } else {
 1414                       form = new MessageFormat(rb.getString
 1415                               (".RETURN.if.same.as.for.otherAlias."));
 1416                       Object[] src = {orig};
 1417                       System.err.print(form.format(src));
 1418                   }
 1419                   System.err.flush();
 1420                   char[] entered = Password.readPassword(System.in);
 1421                   passwords.add(entered);
 1422                   if (entered == null) {
 1423                       return origPass;
 1424                   } else if (entered.length >= 6) {
 1425                       System.err.print(rb.getString("Re.enter.new.password."));
 1426                       char[] passAgain = Password.readPassword(System.in);
 1427                       passwords.add(passAgain);
 1428                       if (!Arrays.equals(entered, passAgain)) {
 1429                           System.err.println
 1430                               (rb.getString("They.don.t.match.Try.again"));
 1431                           continue;
 1432                       }
 1433                       return entered;
 1434                   } else {
 1435                       System.err.println(rb.getString
 1436                           ("Key.password.is.too.short.must.be.at.least.6.characters"));
 1437                   }
 1438               }
 1439               if (count == 3) {
 1440                   if (command == KEYCLONE) {
 1441                       throw new Exception(rb.getString
 1442                           ("Too.many.failures.Key.entry.not.cloned"));
 1443                   } else {
 1444                       throw new Exception(rb.getString
 1445                               ("Too.many.failures.key.not.added.to.keystore"));
 1446                   }
 1447               }
 1448           }
 1449           return null;    // PKCS11
 1450       }
 1451       /**
 1452        * Creates a new secret key.
 1453        */
 1454       private void doGenSecretKey(String alias, String keyAlgName,
 1455                                 int keysize)
 1456           throws Exception
 1457       {
 1458           if (alias == null) {
 1459               alias = keyAlias;
 1460           }
 1461           if (keyStore.containsAlias(alias)) {
 1462               MessageFormat form = new MessageFormat(rb.getString
 1463                   ("Secret.key.not.generated.alias.alias.already.exists"));
 1464               Object[] source = {alias};
 1465               throw new Exception(form.format(source));
 1466           }
 1467   
 1468           SecretKey secKey = null;
 1469           KeyGenerator keygen = KeyGenerator.getInstance(keyAlgName);
 1470           if (keysize != -1) {
 1471               keygen.init(keysize);
 1472           } else if ("DES".equalsIgnoreCase(keyAlgName)) {
 1473               keygen.init(56);
 1474           } else if ("DESede".equalsIgnoreCase(keyAlgName)) {
 1475               keygen.init(168);
 1476           } else {
 1477               throw new Exception(rb.getString
 1478                   ("Please.provide.keysize.for.secret.key.generation"));
 1479           }
 1480   
 1481           secKey = keygen.generateKey();
 1482           if (keyPass == null) {
 1483               keyPass = promptForKeyPass(alias, null, storePass);
 1484           }
 1485           keyStore.setKeyEntry(alias, secKey, keyPass, null);
 1486       }
 1487   
 1488       /**
 1489        * If no signature algorithm was specified at the command line,
 1490        * we choose one that is compatible with the selected private key
 1491        */
 1492       private static String getCompatibleSigAlgName(String keyAlgName)
 1493               throws Exception {
 1494           if ("DSA".equalsIgnoreCase(keyAlgName)) {
 1495               return "SHA1WithDSA";
 1496           } else if ("RSA".equalsIgnoreCase(keyAlgName)) {
 1497               return "SHA256WithRSA";
 1498           } else if ("EC".equalsIgnoreCase(keyAlgName)) {
 1499               return "SHA256withECDSA";
 1500           } else {
 1501               throw new Exception(rb.getString
 1502                       ("Cannot.derive.signature.algorithm"));
 1503           }
 1504       }
 1505       /**
 1506        * Creates a new key pair and self-signed certificate.
 1507        */
 1508       private void doGenKeyPair(String alias, String dname, String keyAlgName,
 1509                                 int keysize, String sigAlgName)
 1510           throws Exception
 1511       {
 1512           if (keysize == -1) {
 1513               if ("EC".equalsIgnoreCase(keyAlgName)) {
 1514                   keysize = 256;
 1515               } else if ("RSA".equalsIgnoreCase(keyAlgName)) {
 1516                   keysize = 2048;
 1517               } else {
 1518                   keysize = 1024;
 1519               }
 1520           }
 1521   
 1522           if (alias == null) {
 1523               alias = keyAlias;
 1524           }
 1525   
 1526           if (keyStore.containsAlias(alias)) {
 1527               MessageFormat form = new MessageFormat(rb.getString
 1528                   ("Key.pair.not.generated.alias.alias.already.exists"));
 1529               Object[] source = {alias};
 1530               throw new Exception(form.format(source));
 1531           }
 1532   
 1533           if (sigAlgName == null) {
 1534               sigAlgName = getCompatibleSigAlgName(keyAlgName);
 1535           }
 1536           CertAndKeyGen keypair =
 1537                   new CertAndKeyGen(keyAlgName, sigAlgName, providerName);
 1538   
 1539   
 1540           // If DN is provided, parse it. Otherwise, prompt the user for it.
 1541           X500Name x500Name;
 1542           if (dname == null) {
 1543               x500Name = getX500Name();
 1544           } else {
 1545               x500Name = new X500Name(dname);
 1546           }
 1547   
 1548           keypair.generate(keysize);
 1549           PrivateKey privKey = keypair.getPrivateKey();
 1550   
 1551           X509Certificate[] chain = new X509Certificate[1];
 1552           chain[0] = keypair.getSelfCertificate(
 1553                   x500Name, getStartDate(startDate), validity*24L*60L*60L);
 1554   
 1555           if (verbose) {
 1556               MessageFormat form = new MessageFormat(rb.getString
 1557                   ("Generating.keysize.bit.keyAlgName.key.pair.and.self.signed.certificate.sigAlgName.with.a.validity.of.validality.days.for"));
 1558               Object[] source = {new Integer(keysize),
 1559                                   privKey.getAlgorithm(),
 1560                                   chain[0].getSigAlgName(),
 1561                                   new Long(validity),
 1562                                   x500Name};
 1563               System.err.println(form.format(source));
 1564           }
 1565   
 1566           if (keyPass == null) {
 1567               keyPass = promptForKeyPass(alias, null, storePass);
 1568           }
 1569           keyStore.setKeyEntry(alias, privKey, keyPass, chain);
 1570   
 1571           // resign so that -ext are applied.
 1572           doSelfCert(alias, null, sigAlgName);
 1573       }
 1574   
 1575       /**
 1576        * Clones an entry
 1577        * @param orig original alias
 1578        * @param dest destination alias
 1579        * @changePassword if the password can be changed
 1580        */
 1581       private void doCloneEntry(String orig, String dest, boolean changePassword)
 1582           throws Exception
 1583       {
 1584           if (orig == null) {
 1585               orig = keyAlias;
 1586           }
 1587   
 1588           if (keyStore.containsAlias(dest)) {
 1589               MessageFormat form = new MessageFormat
 1590                   (rb.getString("Destination.alias.dest.already.exists"));
 1591               Object[] source = {dest};
 1592               throw new Exception(form.format(source));
 1593           }
 1594   
 1595           Pair<Entry,char[]> objs = recoverEntry(keyStore, orig, storePass, keyPass);
 1596           Entry entry = objs.fst;
 1597           keyPass = objs.snd;
 1598   
 1599           PasswordProtection pp = null;
 1600   
 1601           if (keyPass != null) {  // protected
 1602               if (!changePassword || P12KEYSTORE.equalsIgnoreCase(storetype)) {
 1603                   keyPassNew = keyPass;
 1604               } else {
 1605                   if (keyPassNew == null) {
 1606                       keyPassNew = promptForKeyPass(dest, orig, keyPass);
 1607                   }
 1608               }
 1609               pp = new PasswordProtection(keyPassNew);
 1610           }
 1611           keyStore.setEntry(dest, entry, pp);
 1612       }
 1613   
 1614       /**
 1615        * Changes a key password.
 1616        */
 1617       private void doChangeKeyPasswd(String alias) throws Exception
 1618       {
 1619   
 1620           if (alias == null) {
 1621               alias = keyAlias;
 1622           }
 1623           Pair<Key,char[]> objs = recoverKey(alias, storePass, keyPass);
 1624           Key privKey = objs.fst;
 1625           if (keyPass == null) {
 1626               keyPass = objs.snd;
 1627           }
 1628   
 1629           if (keyPassNew == null) {
 1630               MessageFormat form = new MessageFormat
 1631                   (rb.getString("key.password.for.alias."));
 1632               Object[] source = {alias};
 1633               keyPassNew = getNewPasswd(form.format(source), keyPass);
 1634           }
 1635           keyStore.setKeyEntry(alias, privKey, keyPassNew,
 1636                                keyStore.getCertificateChain(alias));
 1637       }
 1638   
 1639       /**
 1640        * Imports a JDK 1.1-style identity database. We can only store one
 1641        * certificate per identity, because we use the identity's name as the
 1642        * alias (which references a keystore entry), and aliases must be unique.
 1643        */
 1644       private void doImportIdentityDatabase(InputStream in)
 1645           throws Exception
 1646       {
 1647           System.err.println(rb.getString
 1648               ("No.entries.from.identity.database.added"));
 1649       }
 1650   
 1651       /**
 1652        * Prints a single keystore entry.
 1653        */
 1654       private void doPrintEntry(String alias, PrintStream out,
 1655                                 boolean printWarning)
 1656           throws Exception
 1657       {
 1658           if (storePass == null && printWarning
 1659                   && !KeyStoreUtil.isWindowsKeyStore(storetype)) {
 1660               printWarning();
 1661           }
 1662   
 1663           if (keyStore.containsAlias(alias) == false) {
 1664               MessageFormat form = new MessageFormat
 1665                   (rb.getString("Alias.alias.does.not.exist"));
 1666               Object[] source = {alias};
 1667               throw new Exception(form.format(source));
 1668           }
 1669   
 1670           if (verbose || rfc || debug) {
 1671               MessageFormat form = new MessageFormat
 1672                   (rb.getString("Alias.name.alias"));
 1673               Object[] source = {alias};
 1674               out.println(form.format(source));
 1675   
 1676               if (!token) {
 1677                   form = new MessageFormat(rb.getString
 1678                       ("Creation.date.keyStore.getCreationDate.alias."));
 1679                   Object[] src = {keyStore.getCreationDate(alias)};
 1680                   out.println(form.format(src));
 1681               }
 1682           } else {
 1683               if (!token) {
 1684                   MessageFormat form = new MessageFormat
 1685                       (rb.getString("alias.keyStore.getCreationDate.alias."));
 1686                   Object[] source = {alias, keyStore.getCreationDate(alias)};
 1687                   out.print(form.format(source));
 1688               } else {
 1689                   MessageFormat form = new MessageFormat
 1690                       (rb.getString("alias."));
 1691                   Object[] source = {alias};
 1692                   out.print(form.format(source));
 1693               }
 1694           }
 1695   
 1696           if (keyStore.entryInstanceOf(alias, KeyStore.SecretKeyEntry.class)) {
 1697               if (verbose || rfc || debug) {
 1698                   Object[] source = {"SecretKeyEntry"};
 1699                   out.println(new MessageFormat(
 1700                           rb.getString("Entry.type.type.")).format(source));
 1701               } else {
 1702                   out.println("SecretKeyEntry, ");
 1703               }
 1704           } else if (keyStore.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) {
 1705               if (verbose || rfc || debug) {
 1706                   Object[] source = {"PrivateKeyEntry"};
 1707                   out.println(new MessageFormat(
 1708                           rb.getString("Entry.type.type.")).format(source));
 1709               } else {
 1710                   out.println("PrivateKeyEntry, ");
 1711               }
 1712   
 1713               // Get the chain
 1714               Certificate[] chain = keyStore.getCertificateChain(alias);
 1715               if (chain != null) {
 1716                   if (verbose || rfc || debug) {
 1717                       out.println(rb.getString
 1718                           ("Certificate.chain.length.") + chain.length);
 1719                       for (int i = 0; i < chain.length; i ++) {
 1720                           MessageFormat form = new MessageFormat
 1721                                   (rb.getString("Certificate.i.1."));
 1722                           Object[] source = {new Integer((i + 1))};
 1723                           out.println(form.format(source));
 1724                           if (verbose && (chain[i] instanceof X509Certificate)) {
 1725                               printX509Cert((X509Certificate)(chain[i]), out);
 1726                           } else if (debug) {
 1727                               out.println(chain[i].toString());
 1728                           } else {
 1729                               dumpCert(chain[i], out);
 1730                           }
 1731                       }
 1732                   } else {
 1733                       // Print the digest of the user cert only
 1734                       out.println
 1735                           (rb.getString("Certificate.fingerprint.SHA1.") +
 1736                           getCertFingerPrint("SHA1", chain[0]));
 1737                   }
 1738               }
 1739           } else if (keyStore.entryInstanceOf(alias,
 1740                   KeyStore.TrustedCertificateEntry.class)) {
 1741               // We have a trusted certificate entry
 1742               Certificate cert = keyStore.getCertificate(alias);
 1743               Object[] source = {"trustedCertEntry"};
 1744               String mf = new MessageFormat(
 1745                       rb.getString("Entry.type.type.")).format(source) + "\n";
 1746               if (verbose && (cert instanceof X509Certificate)) {
 1747                   out.println(mf);
 1748                   printX509Cert((X509Certificate)cert, out);
 1749               } else if (rfc) {
 1750                   out.println(mf);
 1751                   dumpCert(cert, out);
 1752               } else if (debug) {
 1753                   out.println(cert.toString());
 1754               } else {
 1755                   out.println("trustedCertEntry, ");
 1756                   out.println(rb.getString("Certificate.fingerprint.SHA1.")
 1757                               + getCertFingerPrint("SHA1", cert));
 1758               }
 1759           } else {
 1760               out.println(rb.getString("Unknown.Entry.Type"));
 1761           }
 1762       }
 1763   
 1764       /**
 1765        * Load the srckeystore from a stream, used in -importkeystore
 1766        * @returns the src KeyStore
 1767        */
 1768       KeyStore loadSourceKeyStore() throws Exception {
 1769           boolean isPkcs11 = false;
 1770   
 1771           InputStream is = null;
 1772   
 1773           if (P11KEYSTORE.equalsIgnoreCase(srcstoretype) ||
 1774                   KeyStoreUtil.isWindowsKeyStore(srcstoretype)) {
 1775               if (!NONE.equals(srcksfname)) {
 1776                   System.err.println(MessageFormat.format(rb.getString
 1777                       (".keystore.must.be.NONE.if.storetype.is.{0}"), srcstoretype));
 1778                   System.err.println();
 1779                   tinyHelp();
 1780               }
 1781               isPkcs11 = true;
 1782           } else {
 1783               if (srcksfname != null) {
 1784                   File srcksfile = new File(srcksfname);
 1785                       if (srcksfile.exists() && srcksfile.length() == 0) {
 1786                           throw new Exception(rb.getString
 1787                                   ("Source.keystore.file.exists.but.is.empty.") +
 1788                                   srcksfname);
 1789                   }
 1790                   is = new FileInputStream(srcksfile);
 1791               } else {
 1792                   throw new Exception(rb.getString
 1793                           ("Please.specify.srckeystore"));
 1794               }
 1795           }
 1796   
 1797           KeyStore store;
 1798           try {
 1799               if (srcProviderName == null) {
 1800                   store = KeyStore.getInstance(srcstoretype);
 1801               } else {
 1802                   store = KeyStore.getInstance(srcstoretype, srcProviderName);
 1803               }
 1804   
 1805               if (srcstorePass == null
 1806                       && !srcprotectedPath
 1807                       && !KeyStoreUtil.isWindowsKeyStore(srcstoretype)) {
 1808                   System.err.print(rb.getString("Enter.source.keystore.password."));
 1809                   System.err.flush();
 1810                   srcstorePass = Password.readPassword(System.in);
 1811                   passwords.add(srcstorePass);
 1812               }
 1813   
 1814               // always let keypass be storepass when using pkcs12
 1815               if (P12KEYSTORE.equalsIgnoreCase(srcstoretype)) {
 1816                   if (srckeyPass != null && srcstorePass != null &&
 1817                           !Arrays.equals(srcstorePass, srckeyPass)) {
 1818                       MessageFormat form = new MessageFormat(rb.getString(
 1819                           "Warning.Different.store.and.key.passwords.not.supported.for.PKCS12.KeyStores.Ignoring.user.specified.command.value."));
 1820                       Object[] source = {"-srckeypass"};
 1821                       System.err.println(form.format(source));
 1822                       srckeyPass = srcstorePass;
 1823                   }
 1824               }
 1825   
 1826               store.load(is, srcstorePass);   // "is" already null in PKCS11
 1827           } finally {
 1828               if (is != null) {
 1829                   is.close();
 1830               }
 1831           }
 1832   
 1833           if (srcstorePass == null
 1834                   && !KeyStoreUtil.isWindowsKeyStore(srcstoretype)) {
 1835               // anti refactoring, copied from printWarning(),
 1836               // but change 2 lines
 1837               System.err.println();
 1838               System.err.println(rb.getString
 1839                   (".WARNING.WARNING.WARNING."));
 1840               System.err.println(rb.getString
 1841                   (".The.integrity.of.the.information.stored.in.the.srckeystore."));
 1842               System.err.println(rb.getString
 1843                   (".WARNING.WARNING.WARNING."));
 1844               System.err.println();
 1845           }
 1846   
 1847           return store;
 1848       }
 1849   
 1850       /**
 1851        * import all keys and certs from importkeystore.
 1852        * keep alias unchanged if no name conflict, otherwise, prompt.
 1853        * keep keypass unchanged for keys
 1854        */
 1855       private void doImportKeyStore() throws Exception {
 1856   
 1857           if (alias != null) {
 1858               doImportKeyStoreSingle(loadSourceKeyStore(), alias);
 1859           } else {
 1860               if (dest != null || srckeyPass != null || destKeyPass != null) {
 1861                   throw new Exception(rb.getString(
 1862                           "if.alias.not.specified.destalias.srckeypass.and.destkeypass.must.not.be.specified"));
 1863               }
 1864               doImportKeyStoreAll(loadSourceKeyStore());
 1865           }
 1866           /*
 1867            * Information display rule of -importkeystore
 1868            * 1. inside single, shows failure
 1869            * 2. inside all, shows sucess
 1870            * 3. inside all where there is a failure, prompt for continue
 1871            * 4. at the final of all, shows summary
 1872            */
 1873       }
 1874   
 1875       /**
 1876        * Import a single entry named alias from srckeystore
 1877        * @returns 1 if the import action succeed
 1878        *          0 if user choose to ignore an alias-dumplicated entry
 1879        *          2 if setEntry throws Exception
 1880        */
 1881       private int doImportKeyStoreSingle(KeyStore srckeystore, String alias)
 1882               throws Exception {
 1883   
 1884           String newAlias = (dest==null) ? alias : dest;
 1885   
 1886           if (keyStore.containsAlias(newAlias)) {
 1887               Object[] source = {alias};
 1888               if (noprompt) {
 1889                   System.err.println(new MessageFormat(rb.getString(
 1890                           "Warning.Overwriting.existing.alias.alias.in.destination.keystore")).format(source));
 1891               } else {
 1892                   String reply = getYesNoReply(new MessageFormat(rb.getString(
 1893                           "Existing.entry.alias.alias.exists.overwrite.no.")).format(source));
 1894                   if ("NO".equals(reply)) {
 1895                       newAlias = inputStringFromStdin(rb.getString
 1896                               ("Enter.new.alias.name.RETURN.to.cancel.import.for.this.entry."));
 1897                       if ("".equals(newAlias)) {
 1898                           System.err.println(new MessageFormat(rb.getString(
 1899                                   "Entry.for.alias.alias.not.imported.")).format(
 1900                                   source));
 1901                           return 0;
 1902                       }
 1903                   }
 1904               }
 1905           }
 1906   
 1907           Pair<Entry,char[]> objs = recoverEntry(srckeystore, alias, srcstorePass, srckeyPass);
 1908           Entry entry = objs.fst;
 1909   
 1910           PasswordProtection pp = null;
 1911   
 1912           // According to keytool.html, "The destination entry will be protected
 1913           // using destkeypass. If destkeypass is not provided, the destination
 1914           // entry will be protected with the source entry password."
 1915           // so always try to protect with destKeyPass.
 1916           if (destKeyPass != null) {
 1917               pp = new PasswordProtection(destKeyPass);
 1918           } else if (objs.snd != null) {
 1919               pp = new PasswordProtection(objs.snd);
 1920           }
 1921   
 1922           try {
 1923               keyStore.setEntry(newAlias, entry, pp);
 1924               return 1;
 1925           } catch (KeyStoreException kse) {
 1926               Object[] source2 = {alias, kse.toString()};
 1927               MessageFormat form = new MessageFormat(rb.getString(
 1928                       "Problem.importing.entry.for.alias.alias.exception.Entry.for.alias.alias.not.imported."));
 1929               System.err.println(form.format(source2));
 1930               return 2;
 1931           }
 1932       }
 1933   
 1934       private void doImportKeyStoreAll(KeyStore srckeystore) throws Exception {
 1935   
 1936           int ok = 0;
 1937           int count = srckeystore.size();
 1938           for (Enumeration<String> e = srckeystore.aliases();
 1939                                           e.hasMoreElements(); ) {
 1940               String alias = e.nextElement();
 1941               int result = doImportKeyStoreSingle(srckeystore, alias);
 1942               if (result == 1) {
 1943                   ok++;
 1944                   Object[] source = {alias};
 1945                   MessageFormat form = new MessageFormat(rb.getString("Entry.for.alias.alias.successfully.imported."));
 1946                   System.err.println(form.format(source));
 1947               } else if (result == 2) {
 1948                   if (!noprompt) {
 1949                       String reply = getYesNoReply("Do you want to quit the import process? [no]:  ");
 1950                       if ("YES".equals(reply)) {
 1951                           break;
 1952                       }
 1953                   }
 1954               }
 1955           }
 1956           Object[] source = {ok, count-ok};
 1957           MessageFormat form = new MessageFormat(rb.getString(
 1958                   "Import.command.completed.ok.entries.successfully.imported.fail.entries.failed.or.cancelled"));
 1959           System.err.println(form.format(source));
 1960       }
 1961   
 1962       /**
 1963        * Prints all keystore entries.
 1964        */
 1965       private void doPrintEntries(PrintStream out)
 1966           throws Exception
 1967       {
 1968           if (storePass == null
 1969                   && !KeyStoreUtil.isWindowsKeyStore(storetype)) {
 1970               printWarning();
 1971           } else {
 1972               out.println();
 1973           }
 1974   
 1975           out.println(rb.getString("Keystore.type.") + keyStore.getType());
 1976           out.println(rb.getString("Keystore.provider.") +
 1977                   keyStore.getProvider().getName());
 1978           out.println();
 1979   
 1980           MessageFormat form;
 1981           form = (keyStore.size() == 1) ?
 1982                   new MessageFormat(rb.getString
 1983                           ("Your.keystore.contains.keyStore.size.entry")) :
 1984                   new MessageFormat(rb.getString
 1985                           ("Your.keystore.contains.keyStore.size.entries"));
 1986           Object[] source = {new Integer(keyStore.size())};
 1987           out.println(form.format(source));
 1988           out.println();
 1989   
 1990           for (Enumeration<String> e = keyStore.aliases();
 1991                                           e.hasMoreElements(); ) {
 1992               String alias = e.nextElement();
 1993               doPrintEntry(alias, out, false);
 1994               if (verbose || rfc) {
 1995                   out.println(rb.getString("NEWLINE"));
 1996                   out.println(rb.getString
 1997                           ("STAR"));
 1998                   out.println(rb.getString
 1999                           ("STARNN"));
 2000               }
 2001           }
 2002       }
 2003   
 2004       private static <T> Iterable<T> e2i(final Enumeration<T> e) {
 2005           return new Iterable<T>() {
 2006               @Override
 2007               public Iterator<T> iterator() {
 2008                   return new Iterator<T>() {
 2009                       @Override
 2010                       public boolean hasNext() {
 2011                           return e.hasMoreElements();
 2012                       }
 2013                       @Override
 2014                       public T next() {
 2015                           return e.nextElement();
 2016                       }
 2017                       public void remove() {
 2018                           throw new UnsupportedOperationException("Not supported yet.");
 2019                       }
 2020                   };
 2021               }
 2022           };
 2023       }
 2024   
 2025       /**
 2026        * Loads CRLs from a source. This method is also called in JarSigner.
 2027        * @param src the source, which means System.in if null, or a URI,
 2028        *        or a bare file path name
 2029        */
 2030       public static Collection<? extends CRL> loadCRLs(String src) throws Exception {
 2031           InputStream in = null;
 2032           URI uri = null;
 2033           if (src == null) {
 2034               in = System.in;
 2035           } else {
 2036               try {
 2037                   uri = new URI(src);
 2038                   if (uri.getScheme().equals("ldap")) {
 2039                       // No input stream for LDAP
 2040                   } else {
 2041                       in = uri.toURL().openStream();
 2042                   }
 2043               } catch (Exception e) {
 2044                   try {
 2045                       in = new FileInputStream(src);
 2046                   } catch (Exception e2) {
 2047                       if (uri == null || uri.getScheme() == null) {
 2048                           throw e2;   // More likely a bare file path
 2049                       } else {
 2050                           throw e;    // More likely a protocol or network problem
 2051                       }
 2052                   }
 2053               }
 2054           }
 2055           if (in != null) {
 2056               try {
 2057                   // Read the full stream before feeding to X509Factory,
 2058                   // otherwise, keytool -gencrl | keytool -printcrl
 2059                   // might not work properly, since -gencrl is slow
 2060                   // and there's no data in the pipe at the beginning.
 2061                   ByteArrayOutputStream bout = new ByteArrayOutputStream();
 2062                   byte[] b = new byte[4096];
 2063                   while (true) {
 2064                       int len = in.read(b);
 2065                       if (len < 0) break;
 2066                       bout.write(b, 0, len);
 2067                   }
 2068                   return CertificateFactory.getInstance("X509").generateCRLs(
 2069                           new ByteArrayInputStream(bout.toByteArray()));
 2070               } finally {
 2071                   if (in != System.in) {
 2072                       in.close();
 2073                   }
 2074               }
 2075           } else {    // must be LDAP, and uri is not null
 2076               String path = uri.getPath();
 2077               if (path.charAt(0) == '/') path = path.substring(1);
 2078               LDAPCertStoreHelper h = new LDAPCertStoreHelper();
 2079               CertStore s = h.getCertStore(uri);
 2080               X509CRLSelector sel =
 2081                       h.wrap(new X509CRLSelector(), null, path);
 2082               return s.getCRLs(sel);
 2083           }
 2084       }
 2085   
 2086       /**
 2087        * Returns CRLs described in a X509Certificate's CRLDistributionPoints
 2088        * Extension. Only those containing a general name of type URI are read.
 2089        */
 2090       public static List<CRL> readCRLsFromCert(X509Certificate cert)
 2091               throws Exception {
 2092           List<CRL> crls = new ArrayList<>();
 2093           CRLDistributionPointsExtension ext =
 2094                   X509CertImpl.toImpl(cert).getCRLDistributionPointsExtension();
 2095           if (ext == null) return crls;
 2096           for (DistributionPoint o: (List<DistributionPoint>)
 2097                   ext.get(CRLDistributionPointsExtension.POINTS)) {
 2098               GeneralNames names = o.getFullName();
 2099               if (names != null) {
 2100                   for (GeneralName name: names.names()) {
 2101                       if (name.getType() == GeneralNameInterface.NAME_URI) {
 2102                           URIName uriName = (URIName)name.getName();
 2103                           for (CRL crl: KeyTool.loadCRLs(uriName.getName())) {
 2104                               if (crl instanceof X509CRL) {
 2105                                   crls.add((X509CRL)crl);
 2106                               }
 2107                           }
 2108                           break;  // Different name should point to same CRL
 2109                       }
 2110                   }
 2111               }
 2112           }
 2113           return crls;
 2114       }
 2115   
 2116       private static String verifyCRL(KeyStore ks, CRL crl)
 2117               throws Exception {
 2118           X509CRLImpl xcrl = (X509CRLImpl)crl;
 2119           X500Principal issuer = xcrl.getIssuerX500Principal();
 2120           for (String s: e2i(ks.aliases())) {
 2121               Certificate cert = ks.getCertificate(s);
 2122               if (cert instanceof X509Certificate) {
 2123                   X509Certificate xcert = (X509Certificate)cert;
 2124                   if (xcert.getSubjectX500Principal().equals(issuer)) {
 2125                       try {
 2126                           ((X509CRLImpl)crl).verify(cert.getPublicKey());
 2127                           return s;
 2128                       } catch (Exception e) {
 2129                       }
 2130                   }
 2131               }
 2132           }
 2133           return null;
 2134       }
 2135   
 2136       private void doPrintCRL(String src, PrintStream out)
 2137               throws Exception {
 2138           for (CRL crl: loadCRLs(src)) {
 2139               printCRL(crl, out);
 2140               String issuer = null;
 2141               if (caks != null) {
 2142                   issuer = verifyCRL(caks, crl);
 2143                   if (issuer != null) {
 2144                       System.out.println("Verified by " + issuer + " in cacerts");
 2145                   }
 2146               }
 2147               if (issuer == null && keyStore != null) {
 2148                   issuer = verifyCRL(keyStore, crl);
 2149                   if (issuer != null) {
 2150                       System.out.println("Verified by " + issuer + " in keystore");
 2151                   }
 2152               }
 2153               if (issuer == null) {
 2154                   out.println(rb.getString
 2155                           ("STAR"));
 2156                   out.println("WARNING: not verified. Make sure -keystore and -alias are correct.");
 2157                   out.println(rb.getString
 2158                           ("STARNN"));
 2159               }
 2160           }
 2161       }
 2162   
 2163       private void printCRL(CRL crl, PrintStream out)
 2164               throws Exception {
 2165           if (rfc) {
 2166               X509CRL xcrl = (X509CRL)crl;
 2167               out.println("-----BEGIN X509 CRL-----");
 2168               new BASE64Encoder().encodeBuffer(xcrl.getEncoded(), out);
 2169               out.println("-----END X509 CRL-----");
 2170           } else {
 2171               out.println(crl.toString());
 2172           }
 2173       }
 2174   
 2175       private void doPrintCertReq(InputStream in, PrintStream out)
 2176               throws Exception {
 2177   
 2178           BufferedReader reader = new BufferedReader(new InputStreamReader(in));
 2179           StringBuffer sb = new StringBuffer();
 2180           boolean started = false;
 2181           while (true) {
 2182               String s = reader.readLine();
 2183               if (s == null) break;
 2184               if (!started) {
 2185                   if (s.startsWith("-----")) {
 2186                       started = true;
 2187                   }
 2188               } else {
 2189                   if (s.startsWith("-----")) {
 2190                       break;
 2191                   }
 2192                   sb.append(s);
 2193               }
 2194           }
 2195           PKCS10 req = new PKCS10(new BASE64Decoder().decodeBuffer(new String(sb)));
 2196   
 2197           PublicKey pkey = req.getSubjectPublicKeyInfo();
 2198           out.printf(rb.getString("PKCS.10.Certificate.Request.Version.1.0.Subject.s.Public.Key.s.format.s.key."),
 2199                   req.getSubjectName(), pkey.getFormat(), pkey.getAlgorithm());
 2200           for (PKCS10Attribute attr: req.getAttributes().getAttributes()) {
 2201               ObjectIdentifier oid = attr.getAttributeId();
 2202               if (oid.equals(PKCS9Attribute.EXTENSION_REQUEST_OID)) {
 2203                   CertificateExtensions exts = (CertificateExtensions)attr.getAttributeValue();
 2204                   if (exts != null) {
 2205                       printExtensions(rb.getString("Extension.Request."), exts, out);
 2206                   }
 2207               } else {
 2208                   out.println(attr.getAttributeId());
 2209                   out.println(attr.getAttributeValue());
 2210               }
 2211           }
 2212           if (debug) {
 2213               out.println(req);   // Just to see more, say, public key length...
 2214           }
 2215       }
 2216   
 2217       /**
 2218        * Reads a certificate (or certificate chain) and prints its contents in
 2219        * a human readable format.
 2220        */
 2221       private void printCertFromStream(InputStream in, PrintStream out)
 2222           throws Exception
 2223       {
 2224           Collection<? extends Certificate> c = null;
 2225           try {
 2226               c = cf.generateCertificates(in);
 2227           } catch (CertificateException ce) {
 2228               throw new Exception(rb.getString("Failed.to.parse.input"), ce);
 2229           }
 2230           if (c.isEmpty()) {
 2231               throw new Exception(rb.getString("Empty.input"));
 2232           }
 2233           Certificate[] certs = c.toArray(new Certificate[c.size()]);
 2234           for (int i=0; i<certs.length; i++) {
 2235               X509Certificate x509Cert = null;
 2236               try {
 2237                   x509Cert = (X509Certificate)certs[i];
 2238               } catch (ClassCastException cce) {
 2239                   throw new Exception(rb.getString("Not.X.509.certificate"));
 2240               }
 2241               if (certs.length > 1) {
 2242                   MessageFormat form = new MessageFormat
 2243                           (rb.getString("Certificate.i.1."));
 2244                   Object[] source = {new Integer(i + 1)};
 2245                   out.println(form.format(source));
 2246               }
 2247               if (rfc) dumpCert(x509Cert, out);
 2248               else printX509Cert(x509Cert, out);
 2249               if (i < (certs.length-1)) {
 2250                   out.println();
 2251               }
 2252           }
 2253       }
 2254   
 2255       private void doPrintCert(final PrintStream out) throws Exception {
 2256           if (jarfile != null) {
 2257               JarFile jf = new JarFile(jarfile, true);
 2258               Enumeration<JarEntry> entries = jf.entries();
 2259               Set<CodeSigner> ss = new HashSet<>();
 2260               byte[] buffer = new byte[8192];
 2261               int pos = 0;
 2262               while (entries.hasMoreElements()) {
 2263                   JarEntry je = entries.nextElement();
 2264                   InputStream is = null;
 2265                   try {
 2266                       is = jf.getInputStream(je);
 2267                       while (is.read(buffer) != -1) {
 2268                           // we just read. this will throw a SecurityException
 2269                           // if a signature/digest check fails. This also
 2270                           // populate the signers
 2271                       }
 2272                   } finally {
 2273                       if (is != null) {
 2274                           is.close();
 2275                       }
 2276                   }
 2277                   CodeSigner[] signers = je.getCodeSigners();
 2278                   if (signers != null) {
 2279                       for (CodeSigner signer: signers) {
 2280                           if (!ss.contains(signer)) {
 2281                               ss.add(signer);
 2282                               out.printf(rb.getString("Signer.d."), ++pos);
 2283                               out.println();
 2284                               out.println();
 2285                               out.println(rb.getString("Signature."));
 2286                               out.println();
 2287                               for (Certificate cert: signer.getSignerCertPath().getCertificates()) {
 2288                                   X509Certificate x = (X509Certificate)cert;
 2289                                   if (rfc) {
 2290                                       out.println(rb.getString("Certificate.owner.") + x.getSubjectDN() + "\n");
 2291                                       dumpCert(x, out);
 2292                                   } else {
 2293                                       printX509Cert(x, out);
 2294                                   }
 2295                                   out.println();
 2296                               }
 2297                               Timestamp ts = signer.getTimestamp();
 2298                               if (ts != null) {
 2299                                   out.println(rb.getString("Timestamp."));
 2300                                   out.println();
 2301                                   for (Certificate cert: ts.getSignerCertPath().getCertificates()) {
 2302                                       X509Certificate x = (X509Certificate)cert;
 2303                                       if (rfc) {
 2304                                           out.println(rb.getString("Certificate.owner.") + x.getSubjectDN() + "\n");
 2305                                           dumpCert(x, out);
 2306                                       } else {
 2307                                           printX509Cert(x, out);
 2308                                       }
 2309                                       out.println();
 2310                                   }
 2311                               }
 2312                           }
 2313                       }
 2314                   }
 2315               }
 2316               jf.close();
 2317               if (ss.size() == 0) {
 2318                   out.println(rb.getString("Not.a.signed.jar.file"));
 2319               }
 2320           } else if (sslserver != null) {
 2321               SSLContext sc = SSLContext.getInstance("SSL");
 2322               final boolean[] certPrinted = new boolean[1];
 2323               sc.init(null, new TrustManager[] {
 2324                   new X509TrustManager() {
 2325   
 2326                       public java.security.cert.X509Certificate[] getAcceptedIssuers() {
 2327                           return null;
 2328                       }
 2329   
 2330                       public void checkClientTrusted(
 2331                           java.security.cert.X509Certificate[] certs, String authType) {
 2332                       }
 2333   
 2334                       public void checkServerTrusted(
 2335                               java.security.cert.X509Certificate[] certs, String authType) {
 2336                           for (int i=0; i<certs.length; i++) {
 2337                               X509Certificate cert = certs[i];
 2338                               try {
 2339                                   if (rfc) {
 2340                                       dumpCert(cert, out);
 2341                                   } else {
 2342                                       out.println("Certificate #" + i);
 2343                                       out.println("====================================");
 2344                                       printX509Cert(cert, out);
 2345                                       out.println();
 2346                                   }
 2347                               } catch (Exception e) {
 2348                                   if (debug) {
 2349                                       e.printStackTrace();
 2350                                   }
 2351                               }
 2352                           }
 2353   
 2354                           // Set to true where there's something to print
 2355                           if (certs.length > 0) {
 2356                               certPrinted[0] = true;
 2357                           }
 2358                       }
 2359                   }
 2360               }, null);
 2361               HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
 2362               HttpsURLConnection.setDefaultHostnameVerifier(
 2363                       new HostnameVerifier() {
 2364                           public boolean verify(String hostname, SSLSession session) {
 2365                               return true;
 2366                           }
 2367                       });
 2368               // HTTPS instead of raw SSL, so that -Dhttps.proxyHost and
 2369               // -Dhttps.proxyPort can be used. Since we only go through
 2370               // the handshake process, an HTTPS server is not needed.
 2371               // This program should be able to deal with any SSL-based
 2372               // network service.
 2373               Exception ex = null;
 2374               try {
 2375                   new URL("https://" + sslserver).openConnection().connect();
 2376               } catch (Exception e) {
 2377                   ex = e;
 2378               }
 2379               // If the certs are not printed out, we consider it an error even
 2380               // if the URL connection is successful.
 2381               if (!certPrinted[0]) {
 2382                   Exception e = new Exception(
 2383                           rb.getString("No.certificate.from.the.SSL.server"));
 2384                   if (ex != null) {
 2385                       e.initCause(ex);
 2386                   }
 2387                   throw e;
 2388               }
 2389           } else {
 2390               InputStream inStream = System.in;
 2391               if (filename != null) {
 2392                   inStream = new FileInputStream(filename);
 2393               }
 2394               try {
 2395                   printCertFromStream(inStream, out);
 2396               } finally {
 2397                   if (inStream != System.in) {
 2398                       inStream.close();
 2399                   }
 2400               }
 2401           }
 2402       }
 2403       /**
 2404        * Creates a self-signed certificate, and stores it as a single-element
 2405        * certificate chain.
 2406        */
 2407       private void doSelfCert(String alias, String dname, String sigAlgName)
 2408           throws Exception
 2409       {
 2410           if (alias == null) {
 2411               alias = keyAlias;
 2412           }
 2413   
 2414           Pair<Key,char[]> objs = recoverKey(alias, storePass, keyPass);
 2415           PrivateKey privKey = (PrivateKey)objs.fst;
 2416           if (keyPass == null)
 2417               keyPass = objs.snd;
 2418   
 2419           // Determine the signature algorithm
 2420           if (sigAlgName == null) {
 2421               sigAlgName = getCompatibleSigAlgName(privKey.getAlgorithm());
 2422           }
 2423   
 2424           // Get the old certificate
 2425           Certificate oldCert = keyStore.getCertificate(alias);
 2426           if (oldCert == null) {
 2427               MessageFormat form = new MessageFormat
 2428                   (rb.getString("alias.has.no.public.key"));
 2429               Object[] source = {alias};
 2430               throw new Exception(form.format(source));
 2431           }
 2432           if (!(oldCert instanceof X509Certificate)) {
 2433               MessageFormat form = new MessageFormat
 2434                   (rb.getString("alias.has.no.X.509.certificate"));
 2435               Object[] source = {alias};
 2436               throw new Exception(form.format(source));
 2437           }
 2438   
 2439           // convert to X509CertImpl, so that we can modify selected fields
 2440           // (no public APIs available yet)
 2441           byte[] encoded = oldCert.getEncoded();
 2442           X509CertImpl certImpl = new X509CertImpl(encoded);
 2443           X509CertInfo certInfo = (X509CertInfo)certImpl.get(X509CertImpl.NAME
 2444                                                              + "." +
 2445                                                              X509CertImpl.INFO);
 2446   
 2447           // Extend its validity
 2448           Date firstDate = getStartDate(startDate);
 2449           Date lastDate = new Date();
 2450           lastDate.setTime(firstDate.getTime() + validity*1000L*24L*60L*60L);
 2451           CertificateValidity interval = new CertificateValidity(firstDate,
 2452                                                                  lastDate);
 2453           certInfo.set(X509CertInfo.VALIDITY, interval);
 2454   
 2455           // Make new serial number
 2456           certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(
 2457                       new java.util.Random().nextInt() & 0x7fffffff));
 2458   
 2459           // Set owner and issuer fields
 2460           X500Name owner;
 2461           if (dname == null) {
 2462               // Get the owner name from the certificate
 2463               owner = (X500Name)certInfo.get(X509CertInfo.SUBJECT + "." +
 2464                                              CertificateSubjectName.DN_NAME);
 2465           } else {
 2466               // Use the owner name specified at the command line
 2467               owner = new X500Name(dname);
 2468               certInfo.set(X509CertInfo.SUBJECT + "." +
 2469                            CertificateSubjectName.DN_NAME, owner);
 2470           }
 2471           // Make issuer same as owner (self-signed!)
 2472           certInfo.set(X509CertInfo.ISSUER + "." +
 2473                        CertificateIssuerName.DN_NAME, owner);
 2474   
 2475           // The inner and outer signature algorithms have to match.
 2476           // The way we achieve that is really ugly, but there seems to be no
 2477           // other solution: We first sign the cert, then retrieve the
 2478           // outer sigalg and use it to set the inner sigalg
 2479           X509CertImpl newCert = new X509CertImpl(certInfo);
 2480           newCert.sign(privKey, sigAlgName);
 2481           AlgorithmId sigAlgid = (AlgorithmId)newCert.get(X509CertImpl.SIG_ALG);
 2482           certInfo.set(CertificateAlgorithmId.NAME + "." +
 2483                        CertificateAlgorithmId.ALGORITHM, sigAlgid);
 2484   
 2485           certInfo.set(X509CertInfo.VERSION,
 2486                           new CertificateVersion(CertificateVersion.V3));
 2487   
 2488           CertificateExtensions ext = createV3Extensions(
 2489                   null,
 2490                   (CertificateExtensions)certInfo.get(X509CertInfo.EXTENSIONS),
 2491                   v3ext,
 2492                   oldCert.getPublicKey(),
 2493                   null);
 2494           certInfo.set(X509CertInfo.EXTENSIONS, ext);
 2495           // Sign the new certificate
 2496           newCert = new X509CertImpl(certInfo);
 2497           newCert.sign(privKey, sigAlgName);
 2498   
 2499           // Store the new certificate as a single-element certificate chain
 2500           keyStore.setKeyEntry(alias, privKey,
 2501                                (keyPass != null) ? keyPass : storePass,
 2502                                new Certificate[] { newCert } );
 2503   
 2504           if (verbose) {
 2505               System.err.println(rb.getString("New.certificate.self.signed."));
 2506               System.err.print(newCert.toString());
 2507               System.err.println();
 2508           }
 2509       }
 2510   
 2511       /**
 2512        * Processes a certificate reply from a certificate authority.
 2513        *
 2514        * <p>Builds a certificate chain on top of the certificate reply,
 2515        * using trusted certificates from the keystore. The chain is complete
 2516        * after a self-signed certificate has been encountered. The self-signed
 2517        * certificate is considered a root certificate authority, and is stored
 2518        * at the end of the chain.
 2519        *
 2520        * <p>The newly generated chain replaces the old chain associated with the
 2521        * key entry.
 2522        *
 2523        * @return true if the certificate reply was installed, otherwise false.
 2524        */
 2525       private boolean installReply(String alias, InputStream in)
 2526           throws Exception
 2527       {
 2528           if (alias == null) {
 2529               alias = keyAlias;
 2530           }
 2531   
 2532           Pair<Key,char[]> objs = recoverKey(alias, storePass, keyPass);
 2533           PrivateKey privKey = (PrivateKey)objs.fst;
 2534           if (keyPass == null) {
 2535               keyPass = objs.snd;
 2536           }
 2537   
 2538           Certificate userCert = keyStore.getCertificate(alias);
 2539           if (userCert == null) {
 2540               MessageFormat form = new MessageFormat
 2541                   (rb.getString("alias.has.no.public.key.certificate."));
 2542               Object[] source = {alias};
 2543               throw new Exception(form.format(source));
 2544           }
 2545   
 2546           // Read the certificates in the reply
 2547           Collection<? extends Certificate> c = cf.generateCertificates(in);
 2548           if (c.isEmpty()) {
 2549               throw new Exception(rb.getString("Reply.has.no.certificates"));
 2550           }
 2551           Certificate[] replyCerts = c.toArray(new Certificate[c.size()]);
 2552           Certificate[] newChain;
 2553           if (replyCerts.length == 1) {
 2554               // single-cert reply
 2555               newChain = establishCertChain(userCert, replyCerts[0]);
 2556           } else {
 2557               // cert-chain reply (e.g., PKCS#7)
 2558               newChain = validateReply(alias, userCert, replyCerts);
 2559           }
 2560   
 2561           // Now store the newly established chain in the keystore. The new
 2562           // chain replaces the old one.
 2563           if (newChain != null) {
 2564               keyStore.setKeyEntry(alias, privKey,
 2565                                    (keyPass != null) ? keyPass : storePass,
 2566                                    newChain);
 2567               return true;
 2568           } else {
 2569               return false;
 2570           }
 2571       }
 2572   
 2573       /**
 2574        * Imports a certificate and adds it to the list of trusted certificates.
 2575        *
 2576        * @return true if the certificate was added, otherwise false.
 2577        */
 2578       private boolean addTrustedCert(String alias, InputStream in)
 2579           throws Exception
 2580       {
 2581           if (alias == null) {
 2582               throw new Exception(rb.getString("Must.specify.alias"));
 2583           }
 2584           if (keyStore.containsAlias(alias)) {
 2585               MessageFormat form = new MessageFormat(rb.getString
 2586                   ("Certificate.not.imported.alias.alias.already.exists"));
 2587               Object[] source = {alias};
 2588               throw new Exception(form.format(source));
 2589           }
 2590   
 2591           // Read the certificate
 2592           X509Certificate cert = null;
 2593           try {
 2594               cert = (X509Certificate)cf.generateCertificate(in);
 2595           } catch (ClassCastException cce) {
 2596               throw new Exception(rb.getString("Input.not.an.X.509.certificate"));
 2597           } catch (CertificateException ce) {
 2598               throw new Exception(rb.getString("Input.not.an.X.509.certificate"));
 2599           }
 2600   
 2601           // if certificate is self-signed, make sure it verifies
 2602           boolean selfSigned = false;
 2603           if (isSelfSigned(cert)) {
 2604               cert.verify(cert.getPublicKey());
 2605               selfSigned = true;
 2606           }
 2607   
 2608           if (noprompt) {
 2609               keyStore.setCertificateEntry(alias, cert);
 2610               return true;
 2611           }
 2612   
 2613           // check if cert already exists in keystore
 2614           String reply = null;
 2615           String trustalias = keyStore.getCertificateAlias(cert);
 2616           if (trustalias != null) {
 2617               MessageFormat form = new MessageFormat(rb.getString
 2618                   ("Certificate.already.exists.in.keystore.under.alias.trustalias."));
 2619               Object[] source = {trustalias};
 2620               System.err.println(form.format(source));
 2621               reply = getYesNoReply
 2622                   (rb.getString("Do.you.still.want.to.add.it.no."));
 2623           } else if (selfSigned) {
 2624               if (trustcacerts && (caks != null) &&
 2625                       ((trustalias=caks.getCertificateAlias(cert)) != null)) {
 2626                   MessageFormat form = new MessageFormat(rb.getString
 2627                           ("Certificate.already.exists.in.system.wide.CA.keystore.under.alias.trustalias."));
 2628                   Object[] source = {trustalias};
 2629                   System.err.println(form.format(source));
 2630                   reply = getYesNoReply
 2631                           (rb.getString("Do.you.still.want.to.add.it.to.your.own.keystore.no."));
 2632               }
 2633               if (trustalias == null) {
 2634                   // Print the cert and ask user if they really want to add
 2635                   // it to their keystore
 2636                   printX509Cert(cert, System.out);
 2637                   reply = getYesNoReply
 2638                           (rb.getString("Trust.this.certificate.no."));
 2639               }
 2640           }
 2641           if (reply != null) {
 2642               if ("YES".equals(reply)) {
 2643                   keyStore.setCertificateEntry(alias, cert);
 2644                   return true;
 2645               } else {
 2646                   return false;
 2647               }
 2648           }
 2649   
 2650           // Try to establish trust chain
 2651           try {
 2652               Certificate[] chain = establishCertChain(null, cert);
 2653               if (chain != null) {
 2654                   keyStore.setCertificateEntry(alias, cert);
 2655                   return true;
 2656               }
 2657           } catch (Exception e) {
 2658               // Print the cert and ask user if they really want to add it to
 2659               // their keystore
 2660               printX509Cert(cert, System.out);
 2661               reply = getYesNoReply
 2662                   (rb.getString("Trust.this.certificate.no."));
 2663               if ("YES".equals(reply)) {
 2664                   keyStore.setCertificateEntry(alias, cert);
 2665                   return true;
 2666               } else {
 2667                   return false;
 2668               }
 2669           }
 2670   
 2671           return false;
 2672       }
 2673   
 2674       /**
 2675        * Prompts user for new password. New password must be different from
 2676        * old one.
 2677        *
 2678        * @param prompt the message that gets prompted on the screen
 2679        * @param oldPasswd the current (i.e., old) password
 2680        */
 2681       private char[] getNewPasswd(String prompt, char[] oldPasswd)
 2682           throws Exception
 2683       {
 2684           char[] entered = null;
 2685           char[] reentered = null;
 2686   
 2687           for (int count = 0; count < 3; count++) {
 2688               MessageFormat form = new MessageFormat
 2689                   (rb.getString("New.prompt."));
 2690               Object[] source = {prompt};
 2691               System.err.print(form.format(source));
 2692               entered = Password.readPassword(System.in);
 2693               passwords.add(entered);
 2694               if (entered == null || entered.length < 6) {
 2695                   System.err.println(rb.getString
 2696                       ("Password.is.too.short.must.be.at.least.6.characters"));
 2697               } else if (Arrays.equals(entered, oldPasswd)) {
 2698                   System.err.println(rb.getString("Passwords.must.differ"));
 2699               } else {
 2700                   form = new MessageFormat
 2701                           (rb.getString("Re.enter.new.prompt."));
 2702                   Object[] src = {prompt};
 2703                   System.err.print(form.format(src));
 2704                   reentered = Password.readPassword(System.in);
 2705                   passwords.add(reentered);
 2706                   if (!Arrays.equals(entered, reentered)) {
 2707                       System.err.println
 2708                           (rb.getString("They.don.t.match.Try.again"));
 2709                   } else {
 2710                       Arrays.fill(reentered, ' ');
 2711                       return entered;
 2712                   }
 2713               }
 2714               if (entered != null) {
 2715                   Arrays.fill(entered, ' ');
 2716                   entered = null;
 2717               }
 2718               if (reentered != null) {
 2719                   Arrays.fill(reentered, ' ');
 2720                   reentered = null;
 2721               }
 2722           }
 2723           throw new Exception(rb.getString("Too.many.failures.try.later"));
 2724       }
 2725   
 2726       /**
 2727        * Prompts user for alias name.
 2728        * @param prompt the {0} of "Enter {0} alias name:  " in prompt line
 2729        * @returns the string entered by the user, without the \n at the end
 2730        */
 2731       private String getAlias(String prompt) throws Exception {
 2732           if (prompt != null) {
 2733               MessageFormat form = new MessageFormat
 2734                   (rb.getString("Enter.prompt.alias.name."));
 2735               Object[] source = {prompt};
 2736               System.err.print(form.format(source));
 2737           } else {
 2738               System.err.print(rb.getString("Enter.alias.name."));
 2739           }
 2740           return (new BufferedReader(new InputStreamReader(
 2741                                           System.in))).readLine();
 2742       }
 2743   
 2744       /**
 2745        * Prompts user for an input string from the command line (System.in)
 2746        * @prompt the prompt string printed
 2747        * @returns the string entered by the user, without the \n at the end
 2748        */
 2749       private String inputStringFromStdin(String prompt) throws Exception {
 2750           System.err.print(prompt);
 2751           return (new BufferedReader(new InputStreamReader(
 2752                                           System.in))).readLine();
 2753       }
 2754   
 2755       /**
 2756        * Prompts user for key password. User may select to choose the same
 2757        * password (<code>otherKeyPass</code>) as for <code>otherAlias</code>.
 2758        */
 2759       private char[] getKeyPasswd(String alias, String otherAlias,
 2760                                   char[] otherKeyPass)
 2761           throws Exception
 2762       {
 2763           int count = 0;
 2764           char[] keyPass = null;
 2765   
 2766           do {
 2767               if (otherKeyPass != null) {
 2768                   MessageFormat form = new MessageFormat(rb.getString
 2769                           ("Enter.key.password.for.alias."));
 2770                   Object[] source = {alias};
 2771                   System.err.println(form.format(source));
 2772   
 2773                   form = new MessageFormat(rb.getString
 2774                           (".RETURN.if.same.as.for.otherAlias."));
 2775                   Object[] src = {otherAlias};
 2776                   System.err.print(form.format(src));
 2777               } else {
 2778                   MessageFormat form = new MessageFormat(rb.getString
 2779                           ("Enter.key.password.for.alias."));
 2780                   Object[] source = {alias};
 2781                   System.err.print(form.format(source));
 2782               }
 2783               System.err.flush();
 2784               keyPass = Password.readPassword(System.in);
 2785               passwords.add(keyPass);
 2786               if (keyPass == null) {
 2787                   keyPass = otherKeyPass;
 2788               }
 2789               count++;
 2790           } while ((keyPass == null) && count < 3);
 2791   
 2792           if (keyPass == null) {
 2793               throw new Exception(rb.getString("Too.many.failures.try.later"));
 2794           }
 2795   
 2796           return keyPass;
 2797       }
 2798   
 2799       /**
 2800        * Prints a certificate in a human readable format.
 2801        */
 2802       private void printX509Cert(X509Certificate cert, PrintStream out)
 2803           throws Exception
 2804       {
 2805           /*
 2806           out.println("Owner: "
 2807                       + cert.getSubjectDN().toString()
 2808                       + "\n"
 2809                       + "Issuer: "
 2810                       + cert.getIssuerDN().toString()
 2811                       + "\n"
 2812                       + "Serial number: " + cert.getSerialNumber().toString(16)
 2813                       + "\n"
 2814                       + "Valid from: " + cert.getNotBefore().toString()
 2815                       + " until: " + cert.getNotAfter().toString()
 2816                       + "\n"
 2817                       + "Certificate fingerprints:\n"
 2818                       + "\t MD5:  " + getCertFingerPrint("MD5", cert)
 2819                       + "\n"
 2820                       + "\t SHA1: " + getCertFingerPrint("SHA1", cert));
 2821           */
 2822   
 2823           MessageFormat form = new MessageFormat
 2824                   (rb.getString(".PATTERN.printX509Cert"));
 2825           Object[] source = {cert.getSubjectDN().toString(),
 2826                           cert.getIssuerDN().toString(),
 2827                           cert.getSerialNumber().toString(16),
 2828                           cert.getNotBefore().toString(),
 2829                           cert.getNotAfter().toString(),
 2830                           getCertFingerPrint("MD5", cert),
 2831                           getCertFingerPrint("SHA1", cert),
 2832                           getCertFingerPrint("SHA-256", cert),
 2833                           cert.getSigAlgName(),
 2834                           cert.getVersion()
 2835                           };
 2836           out.println(form.format(source));
 2837   
 2838           if (cert instanceof X509CertImpl) {
 2839               X509CertImpl impl = (X509CertImpl)cert;
 2840               X509CertInfo certInfo = (X509CertInfo)impl.get(X509CertImpl.NAME
 2841                                                              + "." +
 2842                                                              X509CertImpl.INFO);
 2843               CertificateExtensions exts = (CertificateExtensions)
 2844                       certInfo.get(X509CertInfo.EXTENSIONS);
 2845               if (exts != null) {
 2846                   printExtensions(rb.getString("Extensions."), exts, out);
 2847               }
 2848           }
 2849       }
 2850   
 2851       private static void printExtensions(String title, CertificateExtensions exts, PrintStream out)
 2852               throws Exception {
 2853           int extnum = 0;
 2854           Iterator<Extension> i1 = exts.getAllExtensions().iterator();
 2855           Iterator<Extension> i2 = exts.getUnparseableExtensions().values().iterator();
 2856           while (i1.hasNext() || i2.hasNext()) {
 2857               Extension ext = i1.hasNext()?i1.next():i2.next();
 2858               if (extnum == 0) {
 2859                   out.println();
 2860                   out.println(title);
 2861                   out.println();
 2862               }
 2863               out.print("#"+(++extnum)+": "+ ext);
 2864               if (ext.getClass() == Extension.class) {
 2865                   byte[] v = ext.getExtensionValue();
 2866                   if (v.length == 0) {
 2867                       out.println(rb.getString(".Empty.value."));
 2868                   } else {
 2869                       new sun.misc.HexDumpEncoder().encodeBuffer(ext.getExtensionValue(), out);
 2870                       out.println();
 2871                   }
 2872               }
 2873               out.println();
 2874           }
 2875       }
 2876   
 2877       /**
 2878        * Returns true if the certificate is self-signed, false otherwise.
 2879        */
 2880       private boolean isSelfSigned(X509Certificate cert) {
 2881           return signedBy(cert, cert);
 2882       }
 2883   
 2884       private boolean signedBy(X509Certificate end, X509Certificate ca) {
 2885           if (!ca.getSubjectDN().equals(end.getIssuerDN())) {
 2886               return false;
 2887           }
 2888           try {
 2889               end.verify(ca.getPublicKey());
 2890               return true;
 2891           } catch (Exception e) {
 2892               return false;
 2893           }
 2894       }
 2895   
 2896       /**
 2897        * Locates a signer for a given certificate from a given keystore and
 2898        * returns the signer's certificate.
 2899        * @param cert the certificate whose signer is searched, not null
 2900        * @param ks the keystore to search with, not null
 2901        * @return <code>cert</code> itself if it's already inside <code>ks</code>,
 2902        * or a certificate inside <code>ks</code> who signs <code>cert</code>,
 2903        * or null otherwise.
 2904        */
 2905       private static Certificate getTrustedSigner(Certificate cert, KeyStore ks)
 2906               throws Exception {
 2907           if (ks.getCertificateAlias(cert) != null) {
 2908               return cert;
 2909           }
 2910           for (Enumeration<String> aliases = ks.aliases();
 2911                   aliases.hasMoreElements(); ) {
 2912               String name = aliases.nextElement();
 2913               Certificate trustedCert = ks.getCertificate(name);
 2914               if (trustedCert != null) {
 2915                   try {
 2916                       cert.verify(trustedCert.getPublicKey());
 2917                       return trustedCert;
 2918                   } catch (Exception e) {
 2919                       // Not verified, skip to the next one
 2920                   }
 2921               }
 2922           }
 2923           return null;
 2924       }
 2925   
 2926       /**
 2927        * Gets an X.500 name suitable for inclusion in a certification request.
 2928        */
 2929       private X500Name getX500Name() throws IOException {
 2930           BufferedReader in;
 2931           in = new BufferedReader(new InputStreamReader(System.in));
 2932           String commonName = "Unknown";
 2933           String organizationalUnit = "Unknown";
 2934           String organization = "Unknown";
 2935           String city = "Unknown";
 2936           String state = "Unknown";
 2937           String country = "Unknown";
 2938           X500Name name;
 2939           String userInput = null;
 2940   
 2941           int maxRetry = 20;
 2942           do {
 2943               if (maxRetry-- < 0) {
 2944                   throw new RuntimeException(rb.getString(
 2945                           "Too.many.retries.program.terminated"));
 2946               }
 2947               commonName = inputString(in,
 2948                       rb.getString("What.is.your.first.and.last.name."),
 2949                       commonName);
 2950               organizationalUnit = inputString(in,
 2951                       rb.getString
 2952                           ("What.is.the.name.of.your.organizational.unit."),
 2953                       organizationalUnit);
 2954               organization = inputString(in,
 2955                       rb.getString("What.is.the.name.of.your.organization."),
 2956                       organization);
 2957               city = inputString(in,
 2958                       rb.getString("What.is.the.name.of.your.City.or.Locality."),
 2959                       city);
 2960               state = inputString(in,
 2961                       rb.getString("What.is.the.name.of.your.State.or.Province."),
 2962                       state);
 2963               country = inputString(in,
 2964                       rb.getString
 2965                           ("What.is.the.two.letter.country.code.for.this.unit."),
 2966                       country);
 2967               name = new X500Name(commonName, organizationalUnit, organization,
 2968                                   city, state, country);
 2969               MessageFormat form = new MessageFormat
 2970                   (rb.getString("Is.name.correct."));
 2971               Object[] source = {name};
 2972               userInput = inputString
 2973                   (in, form.format(source), rb.getString("no"));
 2974           } while (collator.compare(userInput, rb.getString("yes")) != 0 &&
 2975                    collator.compare(userInput, rb.getString("y")) != 0);
 2976   
 2977           System.err.println();
 2978           return name;
 2979       }
 2980   
 2981       private String inputString(BufferedReader in, String prompt,
 2982                                  String defaultValue)
 2983           throws IOException
 2984       {
 2985           System.err.println(prompt);
 2986           MessageFormat form = new MessageFormat
 2987                   (rb.getString(".defaultValue."));
 2988           Object[] source = {defaultValue};
 2989           System.err.print(form.format(source));
 2990           System.err.flush();
 2991   
 2992           String value = in.readLine();
 2993           if (value == null || collator.compare(value, "") == 0) {
 2994               value = defaultValue;
 2995           }
 2996           return value;
 2997       }
 2998   
 2999       /**
 3000        * Writes an X.509 certificate in base64 or binary encoding to an output
 3001        * stream.
 3002        */
 3003       private void dumpCert(Certificate cert, PrintStream out)
 3004           throws IOException, CertificateException
 3005       {
 3006           if (rfc) {
 3007               BASE64Encoder encoder = new BASE64Encoder();
 3008               out.println(X509Factory.BEGIN_CERT);
 3009               encoder.encodeBuffer(cert.getEncoded(), out);
 3010               out.println(X509Factory.END_CERT);
 3011           } else {
 3012               out.write(cert.getEncoded()); // binary
 3013           }
 3014       }
 3015   
 3016       /**
 3017        * Converts a byte to hex digit and writes to the supplied buffer
 3018        */
 3019       private void byte2hex(byte b, StringBuffer buf) {
 3020           char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
 3021                               '9', 'A', 'B', 'C', 'D', 'E', 'F' };
 3022           int high = ((b & 0xf0) >> 4);
 3023           int low = (b & 0x0f);
 3024           buf.append(hexChars[high]);
 3025           buf.append(hexChars[low]);
 3026       }
 3027   
 3028       /**
 3029        * Converts a byte array to hex string
 3030        */
 3031       private String toHexString(byte[] block) {
 3032           StringBuffer buf = new StringBuffer();
 3033           int len = block.length;
 3034           for (int i = 0; i < len; i++) {
 3035                byte2hex(block[i], buf);
 3036                if (i < len-1) {
 3037                    buf.append(":");
 3038                }
 3039           }
 3040           return buf.toString();
 3041       }
 3042   
 3043       /**
 3044        * Recovers (private) key associated with given alias.
 3045        *
 3046        * @return an array of objects, where the 1st element in the array is the
 3047        * recovered private key, and the 2nd element is the password used to
 3048        * recover it.
 3049        */
 3050       private Pair<Key,char[]> recoverKey(String alias, char[] storePass,
 3051                                          char[] keyPass)
 3052           throws Exception
 3053       {
 3054           Key key = null;
 3055   
 3056           if (keyStore.containsAlias(alias) == false) {
 3057               MessageFormat form = new MessageFormat
 3058                   (rb.getString("Alias.alias.does.not.exist"));
 3059               Object[] source = {alias};
 3060               throw new Exception(form.format(source));
 3061           }
 3062           if (!keyStore.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class) &&
 3063                   !keyStore.entryInstanceOf(alias, KeyStore.SecretKeyEntry.class)) {
 3064               MessageFormat form = new MessageFormat
 3065                   (rb.getString("Alias.alias.has.no.key"));
 3066               Object[] source = {alias};
 3067               throw new Exception(form.format(source));
 3068           }
 3069   
 3070           if (keyPass == null) {
 3071               // Try to recover the key using the keystore password
 3072               try {
 3073                   key = keyStore.getKey(alias, storePass);
 3074   
 3075                   keyPass = storePass;
 3076                   passwords.add(keyPass);
 3077               } catch (UnrecoverableKeyException e) {
 3078                   // Did not work out, so prompt user for key password
 3079                   if (!token) {
 3080                       keyPass = getKeyPasswd(alias, null, null);
 3081                       key = keyStore.getKey(alias, keyPass);
 3082                   } else {
 3083                       throw e;
 3084                   }
 3085               }
 3086           } else {
 3087               key = keyStore.getKey(alias, keyPass);
 3088           }
 3089   
 3090           return Pair.of(key, keyPass);
 3091       }
 3092   
 3093       /**
 3094        * Recovers entry associated with given alias.
 3095        *
 3096        * @return an array of objects, where the 1st element in the array is the
 3097        * recovered entry, and the 2nd element is the password used to
 3098        * recover it (null if no password).
 3099        */
 3100       private Pair<Entry,char[]> recoverEntry(KeyStore ks,
 3101                               String alias,
 3102                               char[] pstore,
 3103                               char[] pkey) throws Exception {
 3104   
 3105           if (ks.containsAlias(alias) == false) {
 3106               MessageFormat form = new MessageFormat
 3107                   (rb.getString("Alias.alias.does.not.exist"));
 3108               Object[] source = {alias};
 3109               throw new Exception(form.format(source));
 3110           }
 3111   
 3112           PasswordProtection pp = null;
 3113           Entry entry;
 3114   
 3115           try {
 3116               // First attempt to access entry without key password
 3117               // (PKCS11 entry or trusted certificate entry, for example)
 3118   
 3119               entry = ks.getEntry(alias, pp);
 3120               pkey = null;
 3121           } catch (UnrecoverableEntryException une) {
 3122   
 3123               if(P11KEYSTORE.equalsIgnoreCase(ks.getType()) ||
 3124                   KeyStoreUtil.isWindowsKeyStore(ks.getType())) {
 3125                   // should not happen, but a possibility
 3126                   throw une;
 3127               }
 3128   
 3129               // entry is protected
 3130   
 3131               if (pkey != null) {
 3132   
 3133                   // try provided key password
 3134   
 3135                   pp = new PasswordProtection(pkey);
 3136                   entry = ks.getEntry(alias, pp);
 3137   
 3138               } else {
 3139   
 3140                   // try store pass
 3141   
 3142                   try {
 3143                       pp = new PasswordProtection(pstore);
 3144                       entry = ks.getEntry(alias, pp);
 3145                       pkey = pstore;
 3146                   } catch (UnrecoverableEntryException une2) {
 3147                       if (P12KEYSTORE.equalsIgnoreCase(ks.getType())) {
 3148   
 3149                           // P12 keystore currently does not support separate
 3150                           // store and entry passwords
 3151   
 3152                           throw une2;
 3153                       } else {
 3154   
 3155                           // prompt for entry password
 3156   
 3157                           pkey = getKeyPasswd(alias, null, null);
 3158                           pp = new PasswordProtection(pkey);
 3159                           entry = ks.getEntry(alias, pp);
 3160                       }
 3161                   }
 3162               }
 3163           }
 3164   
 3165           return Pair.of(entry, pkey);
 3166       }
 3167       /**
 3168        * Gets the requested finger print of the certificate.
 3169        */
 3170       private String getCertFingerPrint(String mdAlg, Certificate cert)
 3171           throws Exception
 3172       {
 3173           byte[] encCertInfo = cert.getEncoded();
 3174           MessageDigest md = MessageDigest.getInstance(mdAlg);
 3175           byte[] digest = md.digest(encCertInfo);
 3176           return toHexString(digest);
 3177       }
 3178   
 3179       /**
 3180        * Prints warning about missing integrity check.
 3181        */
 3182       private void printWarning() {
 3183           System.err.println();
 3184           System.err.println(rb.getString
 3185               (".WARNING.WARNING.WARNING."));
 3186           System.err.println(rb.getString
 3187               (".The.integrity.of.the.information.stored.in.your.keystore."));
 3188           System.err.println(rb.getString
 3189               (".WARNING.WARNING.WARNING."));
 3190           System.err.println();
 3191       }
 3192   
 3193       /**
 3194        * Validates chain in certification reply, and returns the ordered
 3195        * elements of the chain (with user certificate first, and root
 3196        * certificate last in the array).
 3197        *
 3198        * @param alias the alias name
 3199        * @param userCert the user certificate of the alias
 3200        * @param replyCerts the chain provided in the reply
 3201        */
 3202       private Certificate[] validateReply(String alias,
 3203                                           Certificate userCert,
 3204                                           Certificate[] replyCerts)
 3205           throws Exception
 3206       {
 3207           // order the certs in the reply (bottom-up).
 3208           // we know that all certs in the reply are of type X.509, because
 3209           // we parsed them using an X.509 certificate factory
 3210           int i;
 3211           PublicKey userPubKey = userCert.getPublicKey();
 3212           for (i=0; i<replyCerts.length; i++) {
 3213               if (userPubKey.equals(replyCerts[i].getPublicKey())) {
 3214                   break;
 3215               }
 3216           }
 3217           if (i == replyCerts.length) {
 3218               MessageFormat form = new MessageFormat(rb.getString
 3219                   ("Certificate.reply.does.not.contain.public.key.for.alias."));
 3220               Object[] source = {alias};
 3221               throw new Exception(form.format(source));
 3222           }
 3223   
 3224           Certificate tmpCert = replyCerts[0];
 3225           replyCerts[0] = replyCerts[i];
 3226           replyCerts[i] = tmpCert;
 3227   
 3228           X509Certificate thisCert = (X509Certificate)replyCerts[0];
 3229   
 3230           for (i=1; i < replyCerts.length-1; i++) {
 3231               // find a cert in the reply who signs thisCert
 3232               int j;
 3233               for (j=i; j<replyCerts.length; j++) {
 3234                   if (signedBy(thisCert, (X509Certificate)replyCerts[j])) {
 3235                       tmpCert = replyCerts[i];
 3236                       replyCerts[i] = replyCerts[j];
 3237                       replyCerts[j] = tmpCert;
 3238                       thisCert = (X509Certificate)replyCerts[i];
 3239                       break;
 3240                   }
 3241               }
 3242               if (j == replyCerts.length) {
 3243                   throw new Exception
 3244                       (rb.getString("Incomplete.certificate.chain.in.reply"));
 3245               }
 3246           }
 3247   
 3248           if (noprompt) {
 3249               return replyCerts;
 3250           }
 3251   
 3252           // do we trust the cert at the top?
 3253           Certificate topCert = replyCerts[replyCerts.length-1];
 3254           Certificate root = getTrustedSigner(topCert, keyStore);
 3255           if (root == null && trustcacerts && caks != null) {
 3256               root = getTrustedSigner(topCert, caks);
 3257           }
 3258           if (root == null) {
 3259               System.err.println();
 3260               System.err.println
 3261                       (rb.getString("Top.level.certificate.in.reply."));
 3262               printX509Cert((X509Certificate)topCert, System.out);
 3263               System.err.println();
 3264               System.err.print(rb.getString(".is.not.trusted."));
 3265               String reply = getYesNoReply
 3266                       (rb.getString("Install.reply.anyway.no."));
 3267               if ("NO".equals(reply)) {
 3268                   return null;
 3269               }
 3270           } else {
 3271               if (root != topCert) {
 3272                   // append the root CA cert to the chain
 3273                   Certificate[] tmpCerts =
 3274                       new Certificate[replyCerts.length+1];
 3275                   System.arraycopy(replyCerts, 0, tmpCerts, 0,
 3276                                    replyCerts.length);
 3277                   tmpCerts[tmpCerts.length-1] = root;
 3278                   replyCerts = tmpCerts;
 3279               }
 3280           }
 3281   
 3282           return replyCerts;
 3283       }
 3284   
 3285       /**
 3286        * Establishes a certificate chain (using trusted certificates in the
 3287        * keystore), starting with the user certificate
 3288        * and ending at a self-signed certificate found in the keystore.
 3289        *
 3290        * @param userCert the user certificate of the alias
 3291        * @param certToVerify the single certificate provided in the reply
 3292        */
 3293       private Certificate[] establishCertChain(Certificate userCert,
 3294                                                Certificate certToVerify)
 3295           throws Exception
 3296       {
 3297           if (userCert != null) {
 3298               // Make sure that the public key of the certificate reply matches
 3299               // the original public key in the keystore
 3300               PublicKey origPubKey = userCert.getPublicKey();
 3301               PublicKey replyPubKey = certToVerify.getPublicKey();
 3302               if (!origPubKey.equals(replyPubKey)) {
 3303                   throw new Exception(rb.getString
 3304                           ("Public.keys.in.reply.and.keystore.don.t.match"));
 3305               }
 3306   
 3307               // If the two certs are identical, we're done: no need to import
 3308               // anything
 3309               if (certToVerify.equals(userCert)) {
 3310                   throw new Exception(rb.getString
 3311                           ("Certificate.reply.and.certificate.in.keystore.are.identical"));
 3312               }
 3313           }
 3314   
 3315           // Build a hash table of all certificates in the keystore.
 3316           // Use the subject distinguished name as the key into the hash table.
 3317           // All certificates associated with the same subject distinguished
 3318           // name are stored in the same hash table entry as a vector.
 3319           Hashtable<Principal, Vector<Certificate>> certs = null;
 3320           if (keyStore.size() > 0) {
 3321               certs = new Hashtable<Principal, Vector<Certificate>>(11);
 3322               keystorecerts2Hashtable(keyStore, certs);
 3323           }
 3324           if (trustcacerts) {
 3325               if (caks!=null && caks.size()>0) {
 3326                   if (certs == null) {
 3327                       certs = new Hashtable<Principal, Vector<Certificate>>(11);
 3328                   }
 3329                   keystorecerts2Hashtable(caks, certs);
 3330               }
 3331           }
 3332   
 3333           // start building chain
 3334           Vector<Certificate> chain = new Vector<>(2);
 3335           if (buildChain((X509Certificate)certToVerify, chain, certs)) {
 3336               Certificate[] newChain = new Certificate[chain.size()];
 3337               // buildChain() returns chain with self-signed root-cert first and
 3338               // user-cert last, so we need to invert the chain before we store
 3339               // it
 3340               int j=0;
 3341               for (int i=chain.size()-1; i>=0; i--) {
 3342                   newChain[j] = chain.elementAt(i);
 3343                   j++;
 3344               }
 3345               return newChain;
 3346           } else {
 3347               throw new Exception
 3348                   (rb.getString("Failed.to.establish.chain.from.reply"));
 3349           }
 3350       }
 3351   
 3352       /**
 3353        * Recursively tries to establish chain from pool of trusted certs.
 3354        *
 3355        * @param certToVerify the cert that needs to be verified.
 3356        * @param chain the chain that's being built.
 3357        * @param certs the pool of trusted certs
 3358        *
 3359        * @return true if successful, false otherwise.
 3360        */
 3361       private boolean buildChain(X509Certificate certToVerify,
 3362                           Vector<Certificate> chain,
 3363                           Hashtable<Principal, Vector<Certificate>> certs) {
 3364           Principal issuer = certToVerify.getIssuerDN();
 3365           if (isSelfSigned(certToVerify)) {
 3366               // reached self-signed root cert;
 3367               // no verification needed because it's trusted.
 3368               chain.addElement(certToVerify);
 3369               return true;
 3370           }
 3371   
 3372           // Get the issuer's certificate(s)
 3373           Vector<Certificate> vec = certs.get(issuer);
 3374           if (vec == null) {
 3375               return false;
 3376           }
 3377   
 3378           // Try out each certificate in the vector, until we find one
 3379           // whose public key verifies the signature of the certificate
 3380           // in question.
 3381           for (Enumeration<Certificate> issuerCerts = vec.elements();
 3382                issuerCerts.hasMoreElements(); ) {
 3383               X509Certificate issuerCert
 3384                   = (X509Certificate)issuerCerts.nextElement();
 3385               PublicKey issuerPubKey = issuerCert.getPublicKey();
 3386               try {
 3387                   certToVerify.verify(issuerPubKey);
 3388               } catch (Exception e) {
 3389                   continue;
 3390               }
 3391               if (buildChain(issuerCert, chain, certs)) {
 3392                   chain.addElement(certToVerify);
 3393                   return true;
 3394               }
 3395           }
 3396           return false;
 3397       }
 3398   
 3399       /**
 3400        * Prompts user for yes/no decision.
 3401        *
 3402        * @return the user's decision, can only be "YES" or "NO"
 3403        */
 3404       private String getYesNoReply(String prompt)
 3405           throws IOException
 3406       {
 3407           String reply = null;
 3408           int maxRetry = 20;
 3409           do {
 3410               if (maxRetry-- < 0) {
 3411                   throw new RuntimeException(rb.getString(
 3412                           "Too.many.retries.program.terminated"));
 3413               }
 3414               System.err.print(prompt);
 3415               System.err.flush();
 3416               reply = (new BufferedReader(new InputStreamReader
 3417                                           (System.in))).readLine();
 3418               if (collator.compare(reply, "") == 0 ||
 3419                   collator.compare(reply, rb.getString("n")) == 0 ||
 3420                   collator.compare(reply, rb.getString("no")) == 0) {
 3421                   reply = "NO";
 3422               } else if (collator.compare(reply, rb.getString("y")) == 0 ||
 3423                          collator.compare(reply, rb.getString("yes")) == 0) {
 3424                   reply = "YES";
 3425               } else {
 3426                   System.err.println(rb.getString("Wrong.answer.try.again"));
 3427                   reply = null;
 3428               }
 3429           } while (reply == null);
 3430           return reply;
 3431       }
 3432   
 3433       /**
 3434        * Returns the keystore with the configured CA certificates.
 3435        */
 3436       public static KeyStore getCacertsKeyStore()
 3437           throws Exception
 3438       {
 3439           String sep = File.separator;
 3440           File file = new File(System.getProperty("java.home") + sep
 3441                                + "lib" + sep + "security" + sep
 3442                                + "cacerts");
 3443           if (!file.exists()) {
 3444               return null;
 3445           }
 3446           FileInputStream fis = null;
 3447           KeyStore caks = null;
 3448           try {
 3449               fis = new FileInputStream(file);
 3450               caks = KeyStore.getInstance(JKS);
 3451               caks.load(fis, null);
 3452           } finally {
 3453               if (fis != null) {
 3454                   fis.close();
 3455               }
 3456           }
 3457           return caks;
 3458       }
 3459   
 3460       /**
 3461        * Stores the (leaf) certificates of a keystore in a hashtable.
 3462        * All certs belonging to the same CA are stored in a vector that
 3463        * in turn is stored in the hashtable, keyed by the CA's subject DN
 3464        */
 3465       private void keystorecerts2Hashtable(KeyStore ks,
 3466                   Hashtable<Principal, Vector<Certificate>> hash)
 3467           throws Exception {
 3468   
 3469           for (Enumeration<String> aliases = ks.aliases();
 3470                                           aliases.hasMoreElements(); ) {
 3471               String alias = aliases.nextElement();
 3472               Certificate cert = ks.getCertificate(alias);
 3473               if (cert != null) {
 3474                   Principal subjectDN = ((X509Certificate)cert).getSubjectDN();
 3475                   Vector<Certificate> vec = hash.get(subjectDN);
 3476                   if (vec == null) {
 3477                       vec = new Vector<Certificate>();
 3478                       vec.addElement(cert);
 3479                   } else {
 3480                       if (!vec.contains(cert)) {
 3481                           vec.addElement(cert);
 3482                       }
 3483                   }
 3484                   hash.put(subjectDN, vec);
 3485               }
 3486           }
 3487       }
 3488   
 3489       /**
 3490        * Returns the issue time that's specified the -startdate option
 3491        * @param s the value of -startdate option
 3492        */
 3493       private static Date getStartDate(String s) throws IOException {
 3494           Calendar c = new GregorianCalendar();
 3495           if (s != null) {
 3496               IOException ioe = new IOException(
 3497                       rb.getString("Illegal.startdate.value"));
 3498               int len = s.length();
 3499               if (len == 0) {
 3500                   throw ioe;
 3501               }
 3502               if (s.charAt(0) == '-' || s.charAt(0) == '+') {
 3503                   // Form 1: ([+-]nnn[ymdHMS])+
 3504                   int start = 0;
 3505                   while (start < len) {
 3506                       int sign = 0;
 3507                       switch (s.charAt(start)) {
 3508                           case '+': sign = 1; break;
 3509                           case '-': sign = -1; break;
 3510                           default: throw ioe;
 3511                       }
 3512                       int i = start+1;
 3513                       for (; i<len; i++) {
 3514                           char ch = s.charAt(i);
 3515                           if (ch < '0' || ch > '9') break;
 3516                       }
 3517                       if (i == start+1) throw ioe;
 3518                       int number = Integer.parseInt(s.substring(start+1, i));
 3519                       if (i >= len) throw ioe;
 3520                       int unit = 0;
 3521                       switch (s.charAt(i)) {
 3522                           case 'y': unit = Calendar.YEAR; break;
 3523                           case 'm': unit = Calendar.MONTH; break;
 3524                           case 'd': unit = Calendar.DATE; break;
 3525                           case 'H': unit = Calendar.HOUR; break;
 3526                           case 'M': unit = Calendar.MINUTE; break;
 3527                           case 'S': unit = Calendar.SECOND; break;
 3528                           default: throw ioe;
 3529                       }
 3530                       c.add(unit, sign * number);
 3531                       start = i + 1;
 3532                   }
 3533               } else  {
 3534                   // Form 2: [yyyy/mm/dd] [HH:MM:SS]
 3535                   String date = null, time = null;
 3536                   if (len == 19) {
 3537                       date = s.substring(0, 10);
 3538                       time = s.substring(11);
 3539                       if (s.charAt(10) != ' ')
 3540                           throw ioe;
 3541                   } else if (len == 10) {
 3542                       date = s;
 3543                   } else if (len == 8) {
 3544                       time = s;
 3545                   } else {
 3546                       throw ioe;
 3547                   }
 3548                   if (date != null) {
 3549                       if (date.matches("\\d\\d\\d\\d\\/\\d\\d\\/\\d\\d")) {
 3550                           c.set(Integer.valueOf(date.substring(0, 4)),
 3551                                   Integer.valueOf(date.substring(5, 7))-1,
 3552                                   Integer.valueOf(date.substring(8, 10)));
 3553                       } else {
 3554                           throw ioe;
 3555                       }
 3556                   }
 3557                   if (time != null) {
 3558                       if (time.matches("\\d\\d:\\d\\d:\\d\\d")) {
 3559                           c.set(Calendar.HOUR_OF_DAY, Integer.valueOf(time.substring(0, 2)));
 3560                           c.set(Calendar.MINUTE, Integer.valueOf(time.substring(0, 2)));
 3561                           c.set(Calendar.SECOND, Integer.valueOf(time.substring(0, 2)));
 3562                           c.set(Calendar.MILLISECOND, 0);
 3563                       } else {
 3564                           throw ioe;
 3565                       }
 3566                   }
 3567               }
 3568           }
 3569           return c.getTime();
 3570       }
 3571   
 3572       /**
 3573        * Match a command (may be abbreviated) with a command set.
 3574        * @param s the command provided
 3575        * @param list the legal command set. If there is a null, commands after it
 3576        * are regarded experimental, which means they are supported but their
 3577        * existence should not be revealed to user.
 3578        * @return the position of a single match, or -1 if none matched
 3579        * @throws Exception if s is ambiguous
 3580        */
 3581       private static int oneOf(String s, String... list) throws Exception {
 3582           int[] match = new int[list.length];
 3583           int nmatch = 0;
 3584           int experiment = Integer.MAX_VALUE;
 3585           for (int i = 0; i<list.length; i++) {
 3586               String one = list[i];
 3587               if (one == null) {
 3588                   experiment = i;
 3589                   continue;
 3590               }
 3591               if (one.toLowerCase(Locale.ENGLISH)
 3592                       .startsWith(s.toLowerCase(Locale.ENGLISH))) {
 3593                   match[nmatch++] = i;
 3594               } else {
 3595                   StringBuffer sb = new StringBuffer();
 3596                   boolean first = true;
 3597                   for (char c: one.toCharArray()) {
 3598                       if (first) {
 3599                           sb.append(c);
 3600                           first = false;
 3601                       } else {
 3602                           if (!Character.isLowerCase(c)) {
 3603                               sb.append(c);
 3604                           }
 3605                       }
 3606                   }
 3607                   if (sb.toString().equalsIgnoreCase(s)) {
 3608                       match[nmatch++] = i;
 3609                   }
 3610               }
 3611           }
 3612           if (nmatch == 0) {
 3613               return -1;
 3614           } else if (nmatch == 1) {
 3615               return match[0];
 3616           } else {
 3617               // If multiple matches is in experimental commands, ignore them
 3618               if (match[1] > experiment) {
 3619                   return match[0];
 3620               }
 3621               StringBuffer sb = new StringBuffer();
 3622               MessageFormat form = new MessageFormat(rb.getString
 3623                   ("command.{0}.is.ambiguous."));
 3624               Object[] source = {s};
 3625               sb.append(form.format(source));
 3626               sb.append("\n    ");
 3627               for (int i=0; i<nmatch && match[i]<experiment; i++) {
 3628                   sb.append(' ');
 3629                   sb.append(list[match[i]]);
 3630               }
 3631               throw new Exception(sb.toString());
 3632           }
 3633       }
 3634   
 3635       /**
 3636        * Create a GeneralName object from known types
 3637        * @param t one of 5 known types
 3638        * @param v value
 3639        * @return which one
 3640        */
 3641       private GeneralName createGeneralName(String t, String v)
 3642               throws Exception {
 3643           GeneralNameInterface gn;
 3644           int p = oneOf(t, "EMAIL", "URI", "DNS", "IP", "OID");
 3645           if (p < 0) {
 3646               throw new Exception(rb.getString(
 3647                       "Unrecognized.GeneralName.type.") + t);
 3648           }
 3649           switch (p) {
 3650               case 0: gn = new RFC822Name(v); break;
 3651               case 1: gn = new URIName(v); break;
 3652               case 2: gn = new DNSName(v); break;
 3653               case 3: gn = new IPAddressName(v); break;
 3654               default: gn = new OIDName(v); break; //4
 3655           }
 3656           return new GeneralName(gn);
 3657       }
 3658   
 3659       private static final String[] extSupported = {
 3660                           "BasicConstraints",
 3661                           "KeyUsage",
 3662                           "ExtendedKeyUsage",
 3663                           "SubjectAlternativeName",
 3664                           "IssuerAlternativeName",
 3665                           "SubjectInfoAccess",
 3666                           "AuthorityInfoAccess",
 3667                           null,
 3668                           "CRLDistributionPoints",
 3669       };
 3670   
 3671       private ObjectIdentifier findOidForExtName(String type)
 3672               throws Exception {
 3673           switch (oneOf(type, extSupported)) {
 3674               case 0: return PKIXExtensions.BasicConstraints_Id;
 3675               case 1: return PKIXExtensions.KeyUsage_Id;
 3676               case 2: return PKIXExtensions.ExtendedKeyUsage_Id;
 3677               case 3: return PKIXExtensions.SubjectAlternativeName_Id;
 3678               case 4: return PKIXExtensions.IssuerAlternativeName_Id;
 3679               case 5: return PKIXExtensions.SubjectInfoAccess_Id;
 3680               case 6: return PKIXExtensions.AuthInfoAccess_Id;
 3681               case 8: return PKIXExtensions.CRLDistributionPoints_Id;
 3682               default: return new ObjectIdentifier(type);
 3683           }
 3684       }
 3685   
 3686       /**
 3687        * Create X509v3 extensions from a string representation. Note that the
 3688        * SubjectKeyIdentifierExtension will always be created non-critical besides
 3689        * the extension requested in the <code>extstr</code> argument.
 3690        *
 3691        * @param reqex the requested extensions, can be null, used for -gencert
 3692        * @param ext the original extensions, can be null, used for -selfcert
 3693        * @param extstrs -ext values, Read keytool doc
 3694        * @param pkey the public key for the certificate
 3695        * @param akey the public key for the authority (issuer)
 3696        * @return the created CertificateExtensions
 3697        */
 3698       private CertificateExtensions createV3Extensions(
 3699               CertificateExtensions reqex,
 3700               CertificateExtensions ext,
 3701               List <String> extstrs,
 3702               PublicKey pkey,
 3703               PublicKey akey) throws Exception {
 3704   
 3705           if (ext != null && reqex != null) {
 3706               // This should not happen
 3707               throw new Exception("One of request and original should be null.");
 3708           }
 3709           if (ext == null) ext = new CertificateExtensions();
 3710           try {
 3711               // name{:critical}{=value}
 3712               // Honoring requested extensions
 3713               if (reqex != null) {
 3714                   for(String extstr: extstrs) {
 3715                       if (extstr.toLowerCase(Locale.ENGLISH).startsWith("honored=")) {
 3716                           List<String> list = Arrays.asList(
 3717                                   extstr.toLowerCase(Locale.ENGLISH).substring(8).split(","));
 3718                           // First check existence of "all"
 3719                           if (list.contains("all")) {
 3720                               ext = reqex;    // we know ext was null
 3721                           }
 3722                           // one by one for others
 3723                           for (String item: list) {
 3724                               if (item.equals("all")) continue;
 3725   
 3726                               // add or remove
 3727                               boolean add = true;
 3728                               // -1, unchanged, 0 crtical, 1 non-critical
 3729                               int action = -1;
 3730                               String type = null;
 3731                               if (item.startsWith("-")) {
 3732                                   add = false;
 3733                                   type = item.substring(1);
 3734                               } else {
 3735                                   int colonpos = item.indexOf(':');
 3736                                   if (colonpos >= 0) {
 3737                                       type = item.substring(0, colonpos);
 3738                                       action = oneOf(item.substring(colonpos+1),
 3739                                               "critical", "non-critical");
 3740                                       if (action == -1) {
 3741                                           throw new Exception(rb.getString
 3742                                               ("Illegal.value.") + item);
 3743                                       }
 3744                                   }
 3745                               }
 3746                               String n = reqex.getNameByOid(findOidForExtName(type));
 3747                               if (add) {
 3748                                   Extension e = (Extension)reqex.get(n);
 3749                                   if (!e.isCritical() && action == 0
 3750                                           || e.isCritical() && action == 1) {
 3751                                       e = Extension.newExtension(
 3752                                               e.getExtensionId(),
 3753                                               !e.isCritical(),
 3754                                               e.getExtensionValue());
 3755                                       ext.set(n, e);
 3756                                   }
 3757                               } else {
 3758                                   ext.delete(n);
 3759                               }
 3760                           }
 3761                           break;
 3762                       }
 3763                   }
 3764               }
 3765               for(String extstr: extstrs) {
 3766                   String name, value;
 3767                   boolean isCritical = false;
 3768   
 3769                   int eqpos = extstr.indexOf('=');
 3770                   if (eqpos >= 0) {
 3771                       name = extstr.substring(0, eqpos);
 3772                       value = extstr.substring(eqpos+1);
 3773                   } else {
 3774                       name = extstr;
 3775                       value = null;
 3776                   }
 3777   
 3778                   int colonpos = name.indexOf(':');
 3779                   if (colonpos >= 0) {
 3780                       if (oneOf(name.substring(colonpos+1), "critical") == 0) {
 3781                           isCritical = true;
 3782                       }
 3783                       name = name.substring(0, colonpos);
 3784                   }
 3785   
 3786                   if (name.equalsIgnoreCase("honored")) {
 3787                       continue;
 3788                   }
 3789                   int exttype = oneOf(name, extSupported);
 3790                   switch (exttype) {
 3791                       case 0:     // BC
 3792                           int pathLen = -1;
 3793                           boolean isCA = false;
 3794                           if (value == null) {
 3795                               isCA = true;
 3796                           } else {
 3797                               try {   // the abbr format
 3798                                   pathLen = Integer.parseInt(value);
 3799                                   isCA = true;
 3800                               } catch (NumberFormatException ufe) {
 3801                                   // ca:true,pathlen:1
 3802                                   for (String part: value.split(",")) {
 3803                                       String[] nv = part.split(":");
 3804                                       if (nv.length != 2) {
 3805                                           throw new Exception(rb.getString
 3806                                                   ("Illegal.value.") + extstr);
 3807                                       } else {
 3808                                           if (nv[0].equalsIgnoreCase("ca")) {
 3809                                               isCA = Boolean.parseBoolean(nv[1]);
 3810                                           } else if (nv[0].equalsIgnoreCase("pathlen")) {
 3811                                               pathLen = Integer.parseInt(nv[1]);
 3812                                           } else {
 3813                                               throw new Exception(rb.getString
 3814                                                   ("Illegal.value.") + extstr);
 3815                                           }
 3816                                       }
 3817                                   }
 3818                               }
 3819                           }
 3820                           ext.set(BasicConstraintsExtension.NAME,
 3821                                   new BasicConstraintsExtension(isCritical, isCA,
 3822                                   pathLen));
 3823                           break;
 3824                       case 1:     // KU
 3825                           if(value != null) {
 3826                               boolean[] ok = new boolean[9];
 3827                               for (String s: value.split(",")) {
 3828                                   int p = oneOf(s,
 3829                                          "digitalSignature",  // (0),
 3830                                          "nonRepudiation",    // (1)
 3831                                          "keyEncipherment",   // (2),
 3832                                          "dataEncipherment",  // (3),
 3833                                          "keyAgreement",      // (4),
 3834                                          "keyCertSign",       // (5),
 3835                                          "cRLSign",           // (6),
 3836                                          "encipherOnly",      // (7),
 3837                                          "decipherOnly",      // (8)
 3838                                          "contentCommitment"  // also (1)
 3839                                          );
 3840                                   if (p < 0) {
 3841                                       throw new Exception(rb.getString("Unknown.keyUsage.type.") + s);
 3842                                   }
 3843                                   if (p == 9) p = 1;
 3844                                   ok[p] = true;
 3845                               }
 3846                               KeyUsageExtension kue = new KeyUsageExtension(ok);
 3847                               // The above KeyUsageExtension constructor does not
 3848                               // allow isCritical value, so...
 3849                               ext.set(KeyUsageExtension.NAME, Extension.newExtension(
 3850                                       kue.getExtensionId(),
 3851                                       isCritical,
 3852                                       kue.getExtensionValue()));
 3853                           } else {
 3854                               throw new Exception(rb.getString
 3855                                       ("Illegal.value.") + extstr);
 3856                           }
 3857                           break;
 3858                       case 2:     // EKU
 3859                           if(value != null) {
 3860                               Vector<ObjectIdentifier> v = new Vector<>();
 3861                               for (String s: value.split(",")) {
 3862                                   int p = oneOf(s,
 3863                                           "anyExtendedKeyUsage",
 3864                                           "serverAuth",       //1
 3865                                           "clientAuth",       //2
 3866                                           "codeSigning",      //3
 3867                                           "emailProtection",  //4
 3868                                           "",                 //5
 3869                                           "",                 //6
 3870                                           "",                 //7
 3871                                           "timeStamping",     //8
 3872                                           "OCSPSigning"       //9
 3873                                          );
 3874                                   if (p < 0) {
 3875                                       try {
 3876                                           v.add(new ObjectIdentifier(s));
 3877                                       } catch (Exception e) {
 3878                                           throw new Exception(rb.getString(
 3879                                                   "Unknown.extendedkeyUsage.type.") + s);
 3880                                       }
 3881                                   } else if (p == 0) {
 3882                                       v.add(new ObjectIdentifier("2.5.29.37.0"));
 3883                                   } else {
 3884                                       v.add(new ObjectIdentifier("1.3.6.1.5.5.7.3." + p));
 3885                                   }
 3886                               }
 3887                               ext.set(ExtendedKeyUsageExtension.NAME,
 3888                                       new ExtendedKeyUsageExtension(isCritical, v));
 3889                           } else {
 3890                               throw new Exception(rb.getString
 3891                                       ("Illegal.value.") + extstr);
 3892                           }
 3893                           break;
 3894                       case 3:     // SAN
 3895                       case 4:     // IAN
 3896                           if(value != null) {
 3897                               String[] ps = value.split(",");
 3898                               GeneralNames gnames = new GeneralNames();
 3899                               for(String item: ps) {
 3900                                   colonpos = item.indexOf(':');
 3901                                   if (colonpos < 0) {
 3902                                       throw new Exception("Illegal item " + item + " in " + extstr);
 3903                                   }
 3904                                   String t = item.substring(0, colonpos);
 3905                                   String v = item.substring(colonpos+1);
 3906                                   gnames.add(createGeneralName(t, v));
 3907                               }
 3908                               if (exttype == 3) {
 3909                                   ext.set(SubjectAlternativeNameExtension.NAME,
 3910                                           new SubjectAlternativeNameExtension(
 3911                                               isCritical, gnames));
 3912                               } else {
 3913                                   ext.set(IssuerAlternativeNameExtension.NAME,
 3914                                           new IssuerAlternativeNameExtension(
 3915                                               isCritical, gnames));
 3916                               }
 3917                           } else {
 3918                               throw new Exception(rb.getString
 3919                                       ("Illegal.value.") + extstr);
 3920                           }
 3921                           break;
 3922                       case 5:     // SIA, always non-critical
 3923                       case 6:     // AIA, always non-critical
 3924                           if (isCritical) {
 3925                               throw new Exception(rb.getString(
 3926                                       "This.extension.cannot.be.marked.as.critical.") + extstr);
 3927                           }
 3928                           if(value != null) {
 3929                               List<AccessDescription> accessDescriptions =
 3930                                       new ArrayList<>();
 3931                               String[] ps = value.split(",");
 3932                               for(String item: ps) {
 3933                                   colonpos = item.indexOf(':');
 3934                                   int colonpos2 = item.indexOf(':', colonpos+1);
 3935                                   if (colonpos < 0 || colonpos2 < 0) {
 3936                                       throw new Exception(rb.getString
 3937                                               ("Illegal.value.") + extstr);
 3938                                   }
 3939                                   String m = item.substring(0, colonpos);
 3940                                   String t = item.substring(colonpos+1, colonpos2);
 3941                                   String v = item.substring(colonpos2+1);
 3942                                   int p = oneOf(m,
 3943                                           "",
 3944                                           "ocsp",         //1
 3945                                           "caIssuers",    //2
 3946                                           "timeStamping", //3
 3947                                           "",
 3948                                           "caRepository"  //5
 3949                                           );
 3950                                   ObjectIdentifier oid;
 3951                                   if (p < 0) {
 3952                                       try {
 3953                                           oid = new ObjectIdentifier(m);
 3954                                       } catch (Exception e) {
 3955                                           throw new Exception(rb.getString(
 3956                                                   "Unknown.AccessDescription.type.") + m);
 3957                                       }
 3958                                   } else {
 3959                                       oid = new ObjectIdentifier("1.3.6.1.5.5.7.48." + p);
 3960                                   }
 3961                                   accessDescriptions.add(new AccessDescription(
 3962                                           oid, createGeneralName(t, v)));
 3963                               }
 3964                               if (exttype == 5) {
 3965                                   ext.set(SubjectInfoAccessExtension.NAME,
 3966                                           new SubjectInfoAccessExtension(accessDescriptions));
 3967                               } else {
 3968                                   ext.set(AuthorityInfoAccessExtension.NAME,
 3969                                           new AuthorityInfoAccessExtension(accessDescriptions));
 3970                               }
 3971                           } else {
 3972                               throw new Exception(rb.getString
 3973                                       ("Illegal.value.") + extstr);
 3974                           }
 3975                           break;
 3976                       case 8: // CRL, experimental, only support 1 distributionpoint
 3977                           if(value != null) {
 3978                               String[] ps = value.split(",");
 3979                               GeneralNames gnames = new GeneralNames();
 3980                               for(String item: ps) {
 3981                                   colonpos = item.indexOf(':');
 3982                                   if (colonpos < 0) {
 3983                                       throw new Exception("Illegal item " + item + " in " + extstr);
 3984                                   }
 3985                                   String t = item.substring(0, colonpos);
 3986                                   String v = item.substring(colonpos+1);
 3987                                   gnames.add(createGeneralName(t, v));
 3988                               }
 3989                               ext.set(CRLDistributionPointsExtension.NAME,
 3990                                       new CRLDistributionPointsExtension(
 3991                                           isCritical, Collections.singletonList(
 3992                                           new DistributionPoint(gnames, null, null))));
 3993                           } else {
 3994                               throw new Exception(rb.getString
 3995                                       ("Illegal.value.") + extstr);
 3996                           }
 3997                           break;
 3998                       case -1:
 3999                           ObjectIdentifier oid = new ObjectIdentifier(name);
 4000                           byte[] data = null;
 4001                           if (value != null) {
 4002                               data = new byte[value.length() / 2 + 1];
 4003                               int pos = 0;
 4004                               for (char c: value.toCharArray()) {
 4005                                   int hex;
 4006                                   if (c >= '0' && c <= '9') {
 4007                                       hex = c - '0' ;
 4008                                   } else if (c >= 'A' && c <= 'F') {
 4009                                       hex = c - 'A' + 10;
 4010                                   } else if (c >= 'a' && c <= 'f') {
 4011                                       hex = c - 'a' + 10;
 4012                                   } else {
 4013                                       continue;
 4014                                   }
 4015                                   if (pos % 2 == 0) {
 4016                                       data[pos/2] = (byte)(hex << 4);
 4017                                   } else {
 4018                                       data[pos/2] += hex;
 4019                                   }
 4020                                   pos++;
 4021                               }
 4022                               if (pos % 2 != 0) {
 4023                                   throw new Exception(rb.getString(
 4024                                           "Odd.number.of.hex.digits.found.") + extstr);
 4025                               }
 4026                               data = Arrays.copyOf(data, pos/2);
 4027                           } else {
 4028                               data = new byte[0];
 4029                           }
 4030                           ext.set(oid.toString(), new Extension(oid, isCritical,
 4031                                   new DerValue(DerValue.tag_OctetString, data)
 4032                                           .toByteArray()));
 4033                           break;
 4034                       default:
 4035                           throw new Exception(rb.getString(
 4036                                   "Unknown.extension.type.") + extstr);
 4037                   }
 4038               }
 4039               // always non-critical
 4040               ext.set(SubjectKeyIdentifierExtension.NAME,
 4041                       new SubjectKeyIdentifierExtension(
 4042                           new KeyIdentifier(pkey).getIdentifier()));
 4043               if (akey != null && !pkey.equals(akey)) {
 4044                   ext.set(AuthorityKeyIdentifierExtension.NAME,
 4045                           new AuthorityKeyIdentifierExtension(
 4046                           new KeyIdentifier(akey), null, null));
 4047               }
 4048           } catch(IOException e) {
 4049               throw new RuntimeException(e);
 4050           }
 4051           return ext;
 4052       }
 4053   
 4054       /**
 4055        * Prints the usage of this tool.
 4056        */
 4057       private void usage() {
 4058           if (command != null) {
 4059               System.err.println("keytool " + command +
 4060                       rb.getString(".OPTION."));
 4061               System.err.println();
 4062               System.err.println(rb.getString(command.description));
 4063               System.err.println();
 4064               System.err.println(rb.getString("Options."));
 4065               System.err.println();
 4066   
 4067               // Left and right sides of the options list
 4068               String[] left = new String[command.options.length];
 4069               String[] right = new String[command.options.length];
 4070   
 4071               // Check if there's an unknown option
 4072               boolean found = false;
 4073   
 4074               // Length of left side of options list
 4075               int lenLeft = 0;
 4076               for (int j=0; j<left.length; j++) {
 4077                   Option opt = command.options[j];
 4078                   left[j] = opt.toString();
 4079                   if (opt.arg != null) left[j] += " " + opt.arg;
 4080                   if (left[j].length() > lenLeft) {
 4081                       lenLeft = left[j].length();
 4082                   }
 4083                   right[j] = rb.getString(opt.description);
 4084               }
 4085               for (int j=0; j<left.length; j++) {
 4086                   System.err.printf(" %-" + lenLeft + "s  %s\n",
 4087                           left[j], right[j]);
 4088               }
 4089               System.err.println();
 4090               System.err.println(rb.getString(
 4091                       "Use.keytool.help.for.all.available.commands"));
 4092           } else {
 4093               System.err.println(rb.getString(
 4094                       "Key.and.Certificate.Management.Tool"));
 4095               System.err.println();
 4096               System.err.println(rb.getString("Commands."));
 4097               System.err.println();
 4098               for (Command c: Command.values()) {
 4099                   if (c == KEYCLONE) break;
 4100                   System.err.printf(" %-20s%s\n", c, rb.getString(c.description));
 4101               }
 4102               System.err.println();
 4103               System.err.println(rb.getString(
 4104                       "Use.keytool.command.name.help.for.usage.of.command.name"));
 4105           }
 4106       }
 4107   
 4108       private void tinyHelp() {
 4109           usage();
 4110           if (debug) {
 4111               throw new RuntimeException("NO BIG ERROR, SORRY");
 4112           } else {
 4113               System.exit(1);
 4114           }
 4115       }
 4116   
 4117       private void errorNeedArgument(String flag) {
 4118           Object[] source = {flag};
 4119           System.err.println(new MessageFormat(
 4120                   rb.getString("Command.option.flag.needs.an.argument.")).format(source));
 4121           tinyHelp();
 4122       }
 4123   
 4124       private char[] getPass(String modifier, String arg) {
 4125           char[] output = getPassWithModifier(modifier, arg);
 4126           if (output != null) return output;
 4127           tinyHelp();
 4128           return null;    // Useless, tinyHelp() already exits.
 4129       }
 4130   
 4131       // This method also used by JarSigner
 4132       public static char[] getPassWithModifier(String modifier, String arg) {
 4133           if (modifier == null) {
 4134               return arg.toCharArray();
 4135           } else if (collator.compare(modifier, "env") == 0) {
 4136               String value = System.getenv(arg);
 4137               if (value == null) {
 4138                   System.err.println(rb.getString(
 4139                           "Cannot.find.environment.variable.") + arg);
 4140                   return null;
 4141               } else {
 4142                   return value.toCharArray();
 4143               }
 4144           } else if (collator.compare(modifier, "file") == 0) {
 4145               try {
 4146                   URL url = null;
 4147                   try {
 4148                       url = new URL(arg);
 4149                   } catch (java.net.MalformedURLException mue) {
 4150                       File f = new File(arg);
 4151                       if (f.exists()) {
 4152                           url = f.toURI().toURL();
 4153                       } else {
 4154                           System.err.println(rb.getString(
 4155                                   "Cannot.find.file.") + arg);
 4156                           return null;
 4157                       }
 4158                   }
 4159                   BufferedReader br = new BufferedReader(new InputStreamReader(
 4160                               url.openStream()));
 4161                   String value = br.readLine();
 4162                   br.close();
 4163                   if (value == null) {
 4164                       return new char[0];
 4165                   } else {
 4166                       return value.toCharArray();
 4167                   }
 4168               } catch (IOException ioe) {
 4169                   System.err.println(ioe);
 4170                   return null;
 4171               }
 4172           } else {
 4173               System.err.println(rb.getString("Unknown.password.type.") +
 4174                       modifier);
 4175               return null;
 4176           }
 4177       }
 4178   }
 4179   
 4180   // This class is exactly the same as com.sun.tools.javac.util.Pair,
 4181   // it's copied here since the original one is not included in JRE.
 4182   class Pair<A, B> {
 4183   
 4184       public final A fst;
 4185       public final B snd;
 4186   
 4187       public Pair(A fst, B snd) {
 4188           this.fst = fst;
 4189           this.snd = snd;
 4190       }
 4191   
 4192       public String toString() {
 4193           return "Pair[" + fst + "," + snd + "]";
 4194       }
 4195   
 4196       private static boolean equals(Object x, Object y) {
 4197           return (x == null && y == null) || (x != null && x.equals(y));
 4198       }
 4199   
 4200       public boolean equals(Object other) {
 4201           return
 4202               other instanceof Pair &&
 4203               equals(fst, ((Pair)other).fst) &&
 4204               equals(snd, ((Pair)other).snd);
 4205       }
 4206   
 4207       public int hashCode() {
 4208           if (fst == null) return (snd == null) ? 0 : snd.hashCode() + 1;
 4209           else if (snd == null) return fst.hashCode() + 2;
 4210           else return fst.hashCode() * 17 + snd.hashCode();
 4211       }
 4212   
 4213       public static <A,B> Pair<A,B> of(A a, B b) {
 4214           return new Pair<>(a,b);
 4215       }
 4216   }
 4217   

  Save This Page Home » openjdk-7 » sun.security » tools » [javadoc | source]