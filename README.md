#Securing Android Project TUM Praktikum WS 2015-2016


Following is the technical report about the project. It may be a bit too much information if you just want to use the app but if you want to take a closer look at the structure of the project, it may be useful.

## DroidForce Introduction

### A peak into security

Individuals, organizations, and large form companies all share an interest in protecting different forms of information. Intellectual properties, trade secrets, sensitive information, personal data, are all potential targets for hackers and organizations which could be used for money extortion, blackmail, or other destructive purposes. 
The unwanted or unintended leakage of information to third-parties like this is therefore an issue, and the importance of proper security should supposedly be of great interest. However, a recent report from McAfee shows that the number of cyber attacks is increasing, showing in the potential profit made from this kind of business. Furthermore, the report admits in the unexpected transformation of cybercrime into a full industrial business, suggesting that the awareness of security and solutions for countermeasures should be taken seriously.

Smartphones are in today's society more or less considered to be a mobile personal inventory that can be accessed by the user at any given time. These devices have a built-in nature to always be connected to different networks and services (e.g. Mobile-data, LTE, GPS) due to consumer expectations and marketing standards. The mobile applications that uses these functions is available for download on the Google Play store (android), or iTunes (iOS), and the number of them is increasing continuously. As a result, the time and resource required to properly scrutinize every single one of them is close to impossible. Put these facts together and it is pretty easy to imagine that sensitive data is at a high risk of escaping out of users control.

Pre-installed applications that comes with a brand new device usually does not cover all of the usage a unit goes through during its lifetime. Consumers who are seeking new interesting features for their devices can with a few touches download and install any published application available to them. The only thing acting as intervention is the acceptance of user-permissions and the consumers trust of the applications intentions. As the vast majority of users cannot judge the trustworthiness of the code that is contained within the application, ill-intentioned software will slip by unnoticed. Furthermore, users currently does not have that much power regarding the installation process in terms of control. For example, an application may request the permission to the user's contact information and internet access, seemingly not in need of one or the other but insisting that it will not function properly without both. In the end the user grants both permissions due to these limitations and runs the risk of malicious software accessing personal data.

I an attempt to reduce the number of malicous software on the market, Google introduced "Bouncer" which scans applications currently published in the Google Play Store, as well as when applications are being uploaded for the first time, or when it receives updates. However, this Bouncer has proven to be not the most effecient security guard when, much like a real life bouncer, it encounters something that looks proper, feels safe, and behaves according to the rules, it gives free passage. While it does have the ability to detect noisy or suspicious application and bring them down -one might question the implementation of Bouncer otherwise- there is still reason to remain cautious about which software that is installed on a device.

Let us imagine a scenario where an individual, let us say Tim, is looking for a new text-message application. Tim enters the Google play store and finds a promising application and downloads it. Now, for all Tim knows the application is working as it should: he can contact his friends, send messages, they can exchange photos, movies, call each other, etc. But beneath this seemingly innocent functionality, the application is forwarding this information via SMS or MMS to some unbenign source. Too make matters worse, this unknown connection might also have a transaction fee, which would in other words mean that Tim is in fact paying with his own money to get his data stolen. 
If we take this scenario into account, and assume that a malicious software has after all been installed on a device, how do we stop it from sending a users personal information?

We would like to introduce DroidForce!

### A bit of story

DroidForce is a product of the collaboration between researchers from [TUM](http://www.tum.de) and [TU Darmstadt](http://www.tu-darmstadt.de/). A paper has been written about it and is available [here](https://www.dropbox.com/sh/vh3u8exf68qwpg6/AADmCchjZn6I27Z0qR9sPycEa/DROIDFORCE%20Enforcing%20Complex%2C%20Data-Centric%2C%20System-Wide%20Policies%20in%20Android.pdf?dl=0).

The concept behind this implementation is fairly simple, the flow of data on Android devices can be very hard to track: the native Android permission system does have some limitations:
 * You need to accept all permissions to install an app.
 * You cannot see how often a permission is used.
 * You cannot see whom your data is sent to.
 * There can be leaks via the intent system of Android (which is one of the typical design patterns of Android); more about it on Limitations.
 * Android 6 is different in these points, we won't talk about it.


So you may agree on all these points and you ask yourself, **how can an almost unknown software solve what we can call an OS Design Error** (at least, if you care about your privacy)?

### What does DroidForce do?

The idea of DroidForce is pretty radical, it is basically: **"Well, Blackberry tried to secure the OS, they had some trouble... What about securing all apps?"** 

A good consequence of this is that DroidForce doesn't require the root privileges to work properly; it runs on a standard stock Android device.

### But how can the apps be secured?

Every app uses methods to receive data from the system. We name these methods `Sources`, and excluding the native ones (see the [Limitations](https://github.com/lolobosse/Sentinel/wiki/Technical-Report#droidforce-limitations-before-our-project) part), we can track and detect when they're called.
An app also uses some methods to send data to some external services (typically SMS or Server). We name these methods `Sinks` and excluding the native ones, we know the name of them and can detect where they're called in the app.

**So what about analysing the apps by passing them in a script which will mark where these sources and sinks are?**

That's what the InstrumentationPEP project was designed for! It basically takes a few arguments (like which sources and sinks) and injects a boolean check every time one of the source/sink method is called.

### What? A boolean check?

Yes! To be able to see which app is leaking your data and send viruses to its creator is already a really good thing, **what about avoiding these data to be sent?** Wouldn't that be better? And that's the whole point of the `DroidForce` project: we add the boolean check which will basically call a Decision Point at runtime which will then return a boolean based on a user-defined policy.

### Wait, wait policies that I need to define? Decision Point? What are you talking about?

Yep, it's research, it won't be as easy to use as Facebook (but if you land on this page, you're definitely lost or you already have a rough idea of the topic). In order that the Decision Point (which runs in the Sentinel app, but see our Project Part!) is making the right decision, the user needs to define some policies which would be **"I do not want to send SMS to 12345 because it costs me money."** (the good part with computers is that you do not need to explain why). 

Here is a sample of how this policy could look like on DroidForce:

```xml
<?xml version='1.0' standalone='yes'?>
<policy     
    xmlns="http://www22.in.tum.de/enforcementLanguage"
    xmlns:tns="http://www22.in.tum.de/enforcementLanguage" 
    xmlns:a="http://www22.in.tum.de/action"
    xmlns:e="http://www22.in.tum.de/event" 
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    
    name="policyForWiki">

    <preventiveMechanism name="nope" >
        <description>I do not want to send any money to 12345</description>
        <timestep amount="3" unit="SECONDS" />
        <trigger action="sendTextMessage" tryEvent="true" >
            <paramMatch name="destination" value="12345" />
        </trigger>
        <condition>
          <true/>
        </condition>
        <authorizationAction name="default" >
            <inhibit />
        </authorizationAction>
    </preventiveMechanism>
</policy>

```
**Intimidating! Huh?!**
But do not worry, there is some templates and we hope to have more soon!

## DroidForce Limitations before our project

Our Practical Course supervisor made us aware of some limitations of DroidForce that we would somehow need to tackle:
 * User Experience is really bad (we need to download the app, instrument it, move it to the device and then install it, all that from a powerful enough computer).
 * The policies cannot be created/modified on the device.
 * Instrument all the apps of the system is a pain and without doing that, we cannot guarantee that the system is proof because of these possible scenarios:


### Leakage one:
![leakage 1](http://i.imgur.com/c65o1En.png)


### Leakage two:
![leakage 2](http://i.imgur.com/fThGiPf.png)


### Ideal scenario:
![Ideal scenario](http://i.imgur.com/2IAAJFy.png)


 * The native calls are not instrumented at all, so basically instrumenting apps like Facebook, which do a massive usage of native methods (use of the [NDK](http://developer.android.com/tools/sdk/ndk/index.html)), doesn't work.
 * The policy language is not very intuitive (but we broke our teeth on this problem)
 * There a is a critical lack of documentation as it wasn't thought to be used by external people.

# Our Project
So we are 3 students working on this project: one French (Laurent Meyer, Android Guru, [@lolobosse](https://github.com/lolobosse)), one Swedish (Pontus Andersson, UI/UX Guru, [@Moderbord](https://github.com/Moderbord)) and one German (Sebastian Weitzel, Jersey-DB-RAML-License Guru, [@mlin2](https://github.com/mlin2)).

We tried to tackle some of the issues of DroidForce with a main focus on the user experience which definitely needed to be improved.

## Which problems are we solving?

Enrico Lovat, our supervisor, gave us some leads to improve the quality of `DroidForce` and from among these ideas we chose to do the following:

Our initial objective of the project was: "**We want to create a big central app which could:**"
 * Act as a « Instrumented App Store »
 * Send existing apks to server for instrumentation.
 * Maintain a record of which apps are instrumented.
 * Allow the user to write policies and to send these to the server which will return an instrumented app based on these.

We called this "big central app" `Sentinel`.

The advantages of this approach were the following:
* Doesn’t need to change PEP (Instrumentation code) at all.
* Can create a (small) wave around the project and interest other developers.
* Will allow to test DroidForce on more apps and discover limitations or problems.
* We will get closer to a B2C product quality.

### Out of scope
Another idea that Enrico told us about was to modify the OS directly and trace every app from there. We didn't tackle this problem for a few (good) reasons:
 * None of us has deep knowledge in C++
 * None of us knows the native code of Android
 * It would require more than the timeframe allowed (3 month) to compensate this lack of competence.
 * We would have lost the characteristics of Droid Force: *No root*!
 * None of us found it particularly exciting ;)

## Concretely, what are we going to code?

We'll mostly focus on 2 parts: an Android app, called Sentinel (Laurent and Pontus) which will be responsible for creating/modifying/deploy policies and send/download/install apps and a server (Sebastian) which will hash/store/instrument/return the apps.

A good overview of the basic structure is illustrated with this scheme:

![Server workflow](http://i.imgur.com/GcKDHZ3.png)

*Note that this does not cover the workflow of the whole application*

#App Sentinel

## Requirements
The app is running from Android versions 4.0 to 4.4. We could probably have included 6.0 but because we had a critical lack of capacity we didn't test enough on this platform and decided to keep it safe and to focus on the platforms we were really knowing. *LOLLIPOP* will not wot work and the problem is the DroidForce lib (not us!).

## Philosophy of development

The workflow we had for the app was **"we build quick, we improve later"**, so if you look at the commit differences, you should see that they're pretty big and that the project has been rebuilt many times. It's partly due to the fact that the team has been constantly reducing, we were 6 at the beginning which means that we did the whole work with 3 people!

## Code quality and tests

However, along the project we really tried to increase the code quality of the project and we introduced some unit tests, some component testing, and tried to have a decent test coverage. We wrote a lot of Javadoc and have an explicit header for almost every method.

To run the tests, use an **emulator** which respects the requirements of the app (some permission issues could happen on some real devices and **DO NOT USE A GOOGLE EMULATOR**) and use the `./gradlew connectedCheck`. You can access the coverage at `sentinel/build/reports/coverage/debug/index.html` once the tests successfully pass. The coverage could be better but it is sufficient to ensure that the minimum viable features are working: we have the critical buttons displayed at the right moment and we retrieve all apps from the system in order to instrument them. Some other interesting detail: Laurent wrote the unit test and Pontus the Component tests (with the great [Espresso lib](http://google.github.io/android-testing-support-library/docs/espresso/index.html)).

## Policy Editor
This part was supposed to be the easiest of the whole project but it was, by far, the most complicated one: Laurent was responsible for that and made 75% of his changes on this topic.

### What went wrong?
At first, Laurent was having a really bad approach: he took the examples and wrote a decent parser for these example but not for the language as it was defined on the [XSD](https://github.com/lolobosse/DroidForce/blob/master/xsd.zip)

Of course, after a talk with Enrico, it was pretty clear that the idea was extremely bad and that everything needed to be rewritten from scratch to fit the constraints of the XSD definition.

#### XSD Epic Story
It took one day (13 hours precisely) to have the parsing of the XSD perfectly working and bound to the existing UI (which was before bound to the incomplete parser) because there is really no good documentation of how to parse XSD on Android on the Internet (and Laurent is not the kind of guy who will loose hours in exploring source code). 

We could have used [JAXB](https://en.wikipedia.org/wiki/Java_Architecture_for_XML_Binding) (whose [best tutorial](http://www.jmdoudoux.fr/java/dej/chap-jaxb.htm) was in french) but we'd have some troubles which are really well explained [here](http://stackoverflow.com/a/5461155/2545832), so we moved to a much cleaner solution called [Jibx](http://jibx.sourceforge.net/) which is [pretty well documented](http://blog.tourgeek.com/2011/12/xml-data-binding-for-java-on-android.html).

The reasons why `Jibx`is better are:
 * It has been or, at least was, the fastest XML data binding framework for Java.
 * 133 KB jar against 9MB for JAXB
 * It is not hacky to run on Android, you do not need to do [that](http://www.docx4java.org/blog/2012/05/jaxb-can-be-made-to-run-on-android/)

A limitation of Jibx: it fails to retain important information like TimeZone in XML date elements (but we do not care in our case).

Actually this wasn't needed at all because the existing `app-PDPj-lib` is also doing a parsing with a repackaged version of JAXB (so we could have use it), the only problem for the team was we weren't sure if we will be kicking this `appPDPj-lib` from the project because none of us is very keen on its coding style. 

So we found ourselves stuck with that kind of screenshot and wasn't really possible to go further.

![PolicyEditor](http://i.imgur.com/yBHVdoN.png)


Then we met with Enrico (18/01/2016) and it was pretty clear that with the limitations of the OSL (the internal language of DroidForce), Laurent wouldn't be able to meet the highest expectations of Enrico for this feature, and the whole team decided to drop the feature to something as good (or even better) for the end user which would require much less work: a XML Editor. 

There are not that many complete XML Editors on Android with open source, so we used the one which was the most downloaded one on the Play Store: [Axel](https://play.google.com/store/apps/details?id=fr.xgouchet.xmleditor) whose original source is [there](https://github.com/xgouchet/Axel).

#### Open Source, here we come!

As you will see if you clicked on the link, the project is developed using IntelliJ and, as we try to use the latest standards, we needed to move it to Gradle. That's what [Laurent's clone](https://github.com/lolobosse/Axel2) is doing and the changes were so important (lots of 9.png changes, libs moved, submodules deletion...) that we needed to re-push the project totally.
So in some way we respected the rule: we got something from the community and we give some improvements back! :smile: 

Btw, we'd like to thank [@xgouchet](https://github.com/xgouchet) for his support and his advices in order to get the app working.

#### How we ended up?

So, we decided to focus on the next features and to get something okay for the user so we included the app of @xgouchet in the project which is automatically installed when `gradlew install` is run. The user have to choose a policy to edit and he is sent to the Axel XML Editor (btw, we made a [bugfix](https://github.com/lolobosse/DroidForce/commit/3349617628071a4d30971f389fb45909b07d585c#diff-8d44de9faf33925b3fa54c07f38d06e5R617) for 5.0 devices).

Currently looking like this:

![AxelXML](http://i.imgur.com/kidLeMz.png)


## File Explorer

### Why did we create our own file explorer?

For fun and for having a better design! (ok you may find that your file explorer is better than the one we did but the fun is still there!).

Pontus wanted created these classes from A to Z only with a small code review from Laurent at the end and they work perfectly and are almost fully tested (some error branches are missing though). We use them all over the app so that's why we decided to have our own: it is smoother and faster than having external intents (and of course more reliable).

![FileExplorer](http://i.imgur.com/Sc12ftB.png)


Codewise, it's very simple; It starts of by getting the path to the external sdcard and saving that into a `String` value. Out of this string we make a new `File`, and pass it to a method  called "fill" which takes one `File` argument. In this method we list all the files in the filepath that has been given, and store them in a `Array`.

Each file is then displayed via a custom `ListAdapter` with a filename, last modified date, size in kB, and a lightweight icon (directory name, last modified date, number of containing files, and icon). Each file responds to an `OnListItemClick` listener, which depending on filetype, either opens the new directory of files (if folder) by using it with the method previously mentioned, returns its absolute path to parent activity (if appropriate file extension), or make a toast about which file extension that should be selected (file with wrong extension has been selected)

### Limitations of the file explorer:
 * Some design errors like: [this funny one](https://github.com/lolobosse/DroidForce/blob/policyUI/sentinel/src/main/java/de/tum/in/i22/sentinel/android/app/file_explorer/MenuObj.java#L50)
 * It is not possible to select multiple files. 

### What could be improved?
 * Separate icon for each file extension
 * A more convenient system for navigating up and down through directories
 * Possibility to select multiple APK's, or, sinks, sources, and taint wrapper all in one go.

## Play Store View 
Not that much to say about that part because it is a `GridView` and a another `Activity` which just displays and gives the user the possibility to install some of the server's instrumented apps. See the server part for more details.

![PlayStore](http://i.imgur.com/DZ6Tl8X.png)
![PlayStoreDetail](http://i.imgur.com/PbiTmAa.png)

## Networking Stack
We mixed two libraries to do the networking calls because we didn't want to spend any time modding networking libraries. We use [Volley](https://android.googlesource.com/platform/frameworks/volley) for its speed (and the fact that Laurent works with it since 2 years) and its [JSONObjectRequest](http://developer.android.com/training/volley/request.html#request-json) which is in our case very useful (to retrieve the Play Store items). On the other hand, we use [AsyncHttp](https://github.com/koush/AndroidAsync) which is a funny and useful lib which does everything that Volley is not designed to do: large file upload, large file download, webserver...

To test that we used a old pattern: a `S.E.M.A.P.H.O.R.E`: Laurent got the idea from the test of the [original library](https://github.com/koush/AndroidAsync/blob/master/AndroidAsync/test/src/com/koushikdutta/async/test/HttpClientTests.java#L128) and we implemented one, just to be sure that the base of the app was working:

```java
public class UploadTest extends AndroidTestCase {

    String instrumentedFilename = "instrumented.apk";
    String nonInstrumentedFilename = "non_instrumented.apk";

    private static final long TIMEOUT = 200000L;



    @Override
    protected void setUp() throws Exception {
        super.setUp();
        // Put the raw file in the internal files
        Utils.writeToFile(instrumentedFilename, R.raw.instrumented, getContext(), null);
        Utils.writeToFile(nonInstrumentedFilename, R.raw.not_instrumented, getContext(), null);
    }

    public void testGlobalSuccessfulWorkflow() throws Exception {
        final Semaphore semaphore = new Semaphore(0);
        File pathToSources = new File(getContext().getFilesDir(), Constants.SOURCES);
        File pathToSinks = new File(getContext().getFilesDir(), Constants.SINKS);
        File pathToTaintWrapper = new File(getContext().getFilesDir(), Constants.TAINT);
        File apk = new File(getContext().getFilesDir(), nonInstrumentedFilename);
        final String hash = Hash.createHashForFile(apk);
        APKSender.getInstance().sendFiles(pathToSources, pathToSinks, pathToTaintWrapper, apk, new AsyncHttpClient.StringCallback() {
            @Override
            public void onCompleted(Exception e, AsyncHttpResponse asyncHttpResponse, String s) {
                Log.d("UploadTest", "asyncHttpResponse:" + asyncHttpResponse);
                assertEquals("The server didn't return 202", 202, asyncHttpResponse.code());
                semaphore.release();
            }
        }, null, null, null);
        assertTrue("Timeout on upload", semaphore.tryAcquire(TIMEOUT, TimeUnit.MILLISECONDS));

        Thread.sleep(15000);
        // We could maybe have used the same Semaphore, but we find it clearer with two.
        final Semaphore semaphoreSuccessful = new Semaphore(0);
        APKReceiver.getInstance().getFile(hash, new AsyncHttpClient.FileCallback() {
            @Override
            public void onCompleted(Exception e, AsyncHttpResponse asyncHttpResponse, File file) {
                assertEquals("The server didn't return 200", 200, asyncHttpResponse.code());
                String hashInstrumented = Hash.createHashForFile(file);
                assertNotSame("The app is the same, hasn't been instrumented", hash, hashInstrumented);
                semaphoreSuccessful.release();
            }
        });
        assertTrue("Timeout on app retrieving", semaphoreSuccessful.tryAcquire(TIMEOUT, TimeUnit.MILLISECONDS));

    }


    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        // Delete the raw file which have been copied
        File instrumented = new File(getContext().getFilesDir(), instrumentedFilename);
        File notInstrumented = new File(getContext().getFilesDir(), nonInstrumentedFilename);
        instrumented.delete();
        notInstrumented.delete();
    }
}
```

We wanted to put that in the report because we found that this mix of old school computer science and modern mobile development was pretty funny!

## Getting the APK of the device
Getting the APK on the device is something relatively easy because the Android Package Manager delivers the informations we need. However, we do not have any possibility to get the path from that tool. To do so we need to call the internal package manager and our solution is an asynchronous implementation of [this SO Solution](http://stackoverflow.com/a/11013175/2545832). This class could have been moved to an standalone open source project, it may be done in the future.

## Limitations of the app:
 * The app has some useless views like the `ToServerFragment` which doesn't bring a lot to the user
 * Using two networking stacks in the app is a good choice in this context (short timeframe and two very different usages) but **it is absolutely not a good practice**: it can lead to an overconsumption of power due to a bad synchronisation of the call to the network chip. Moreover it increase the size of the RAM used because each lib has its own cache.
 * The process to get the installed APKs could have been an independent open source project included as a submodule; it would have been a better design. We'll try to put this part in a library to "help" the community (Objective: be published on Android Arsenal! :smile: ).
 * Copy the policies from the `res` to the filesystem at the start of the `MainActivity` is not very clever.
 * Testing is far from exhaustive and some parts are not easy to be unit tested.
 * No global error handler in the app: an Exception = a Crash (and it happens quite often).
 * The whole system works only between 4.0 and 4.4 (inclusive)
 * Unable to act as a Decision Point yet.

# Instrumentation Server

That's also an interesting part because we were two teams at the beginning working on the same project: having a server which will be able to run the instrumentation of an app. The approach were very different: Laurent wanted to use some quick and dirty [Flask](http://flask.pocoo.org/) Python script with [Websocket](https://flask-socketio.readthedocs.org/en/latest/) to display the logs. It was actually working very well but we would have issues with the websocket on the mobile (it is doable but it would have required some extra time).

If you're curious about multithreading in Python and Websocket, checkout the repo [here](https://github.com/lolobosse/InstrumentationServer).

The approach of Sebastian was very different and much more academic, he used a [RAML](http://raml.org/) file to define his interface (his endpoints) and generate code from that. Here is the current RAML file for instance:

```raml
#%RAML 1.0
title: IaaS
# description: Instrumentation As A Service
version: v2
protocols: [http, https]
schemas:
  - error: !include schemas/error-schema.json
  - apk: !include schemas/apk-schema.json
  - apks: !include schemas/apks-schema.json
  - hash: !include schemas/hash-schema.json
  - metadata: !include schemas/metadata-schema.json
  - metadataList: !include schemas/metadataList-schema.json
/instrument:
  /withmetadata:
      post:
        description: |
          Instrument an apk file based on the configuration files attached
          to the request and store its logo, app name and package name in the database.
        body:
          multipart/form-data:
            formParameters:
              sourceFile:
                description: Source file containing the android's source methods
                displayName: Source File
                type: file
                required: true
              sinkFile:
                description: Sink file containing the android's sink methods
                displayName: Sink File
                type: file
                required: true
              easyTaintWrapperSource:
                description: |
                  Taint wrapper file containing the android's package names that
                  should be considered during the instrumentation phase
                displayName: Easy Taint Wrapper File
                type: file
                required: true
              apkFile:
                description: APK file that should be instrumented
                displayName: APK File
                type: file
                required: true
              logo:
                description: The logo of the app
                displayName: Logo
                type: file
                required: false
              appName:
                description: The name of the app
                displayName: App Name
                type: string
                required: false
              packagename:
                description: The packagename of the app
                displayName: Package Name
                type: string
                required: false
        responses:
          202:
            body:
              application/json:
                schema: apk
          400:
            body:
              application/json:
                schema: error
  /withoutmetadata:
    post:
      description: |
        Instrument an apk file based on the configuration files attached
        to the request
      body:
        multipart/form-data:
          formParameters:
            sourceFile:
              description: Source file containing the android's source methods
              displayName: Source File
              type: file
              required: true
            sinkFile:
              description: Sink file containing the android's sink methods
              displayName: Sink File
              type: file
              required: true
            easyTaintWrapperSource:
              description: |
                Taint wrapper file containing the android's package names that
                should be considered during the instrumentation phase
              displayName: Easy Taint Wrapper File
              type: file
              required: true
            apkFile:
              description: APK file that should be instrumented
              displayName: APK File
              type: file
              required: true
      responses:
        202:
          body:
            application/json:
              schema: apk
        400:
          body:
            application/json:
              schema: error
  /all:
    description: |
      A count and list of the SHA 512 hashes of all instrumented APKs
    get:
      description: Retrieve a list of instrumented apk files
      responses:
        200:
          body:
            application/json:
              schema: apks
  /{apkHash}:
    get:
      description: |
        Retrieve the binary dump of the instrumented apk file based on its hash sum value.
        The hash value is calculated from the non-instrumented apk with sha512.
      responses:
        200:
          body:
              binary/octet-stream:
        404:
          body:
            application/json:
              schema: error
/metadata:
  /all:
    description: |
      Get a list of all the metadata saved on the server.
    get:
      description: Retrieve a list of all the metadata of all instrumented apps
      responses:
        200:
          body:
            application/json:
              schema: metadataList
  /instrumented:
      description: |
        Get a list of the metadata saved on the server.
      get:
        description: Retrieve a list of all the metadata of all instrumented apps
        responses:
          200:
            body:
              application/json:
                schema: metadataList

  /logo/{apkHash}:
      get:
        description: |
          Retrieve the logo of the APK corresponding to the hash.
        responses:
          200:
            body:
              binary/octet-stream:
          404:
            body:
              application/json:
                schema: error
```

To generate the code from that he uses [this library](https://github.com/mulesoft/raml-for-jax-rs) and it had some important issues concerning the `Multipart` that were already reported [here](https://github.com/mulesoft/raml-for-jax-rs/issues/105)

The code generated is JAX-RS code which is why [Jersey](https://jersey.java.net/) was chosen as an implementation of JAX-RS. Because an JAX-RS implementation is used as a framework for the backend of our instrumentation service, the instrumentation server can be integrated with other JAX-RS implementations or as a servlet with some modification. This allows the project to grow a lot and be easily extensible.

It is also possible to generate documentation from the [RAML](http://raml.org/developers/document-your-api) file. However this doesn't work yet with RAML 1.0 which we used to define the API. The work for it to work seems to be in progress for both html [issue 156](https://github.com/raml2html/raml2html/issues/156) and [issue 153](https://github.com/raml2html/raml2html/issues/153), and the interactive [API browsing issue](https://github.com/mulesoft/api-console/issues/190) (Both work in progress at the time of this writing.)

We created a RAML 0.8 version of of the RAML file to be able to generate the interactive html documentation. It can be found here https://github.com/mlin2/InstrumentationServer/blob/master/raml/iaas-0-8.raml. The documentation itself can be found in the InstrumentationServer project root and is called interactive-api-documentation.html. To view it, just open this file with your browser.

Furthermore, a [Grizzly](https://grizzly.java.net/) HTTP server is used because Grizzly is an [non-blocking](https://en.wikipedia.org/wiki/Non-blocking_I/O_%28Java%29) input output operations framework and will therefore scale well with many requests for instrumentation from many people.

The database used for the project is [SQLite](https://www.sqlite.org/whentouse.html) as it is simple, looked like a good fit for the initial requirements of storing a small table with APK binary data and hashes, and can store terabytes of data  and seems to still offer good performance. Furthermore, it doesn't need to be configured. It turned out that many single insert statements that are currently used to insert the metadata from the F-Droid repository are slow and can take a few minutes. This can probably be improved by using a single big statement to insert the data or using a client/server database management system.

Note: The hashes used in the implementation of the server always correspond to the uninstrumented versions of APKs because we try to receive data from already having an APK that is not yet instrumented.

### Why is all of that cool?
 * If we change the RAML, the endpoints and model classes can be generated again. Therefore much less implementation is required for changing the REST API.
 * It integrates well with Maven
 * It's just clean software engineering.
 * Because we want that other devs try our server code, we made its configuration pretty simple and devs just have to follow the steps described there:
 * Extending the server or including it in a bigger Java server project will be possible.


### Dependencies of the server
We used this instrumentation server implementation on a Debian server. For most of the dependencies below you can use "apt-get install packagename" to install them. 

Install Java http://openjdk.java.net/install/

Install Maven https://maven.apache.org/install.html

Install SQLite https://www.sqlite.org/download.html

Install zipalign http://developer.android.com/tools/help/zipalign.html

Get an android jar http://developer.android.com/sdk/index.html

Generate a [keystore](https://www.digitalocean.com/community/tutorials/java-keytool-essentials-working-with-java-keystores) for signing of APKs and if you want to offer HTTPS support for the certificates as well.

You already should have it if you are running linux but in case you don't, you also need the timeout program that can be found in gnu coreutils.

Furthermore, the operating system running the instrumentation server has to be able to run bash scripts.

All of the above except the android jar file have to be added to your [PATH] (http://unix.stackexchange.com/questions/26047/how-to-correctly-add-a-path-to-path). Alternatively, you can change the bash script "instrumentation.sh" in the projects root folder and add your individual program paths to all the programs that get executed there.

### Running the server
The steps to get the server running are as follows:

Run in a terminal:
```
git clone https://github.com/mlin2/InstrumentationServer.git

cd InstrumentationServer

```
Create a config.ini:
To make things even easier, Laurent creates a config file at the time of the Python server and this `config.ini` file idea was reused by Sebastian in the current server project.
The instrumentation server needs a file named config.ini in the project root folder. This is an example of what the config file must include:
```ini
[URL]
# The URL the server will run on
ServerUrl: https://your.domain.org


[Security]
# Whether or not to enable HTTPS on the server.
enableHTTPS: true

# The absolute path to the app signing keystore
keyStorePathSecurity: your/path/SecurityKeystore

# The password of the security keystore
storePassSecurity: security_password


[Port]
# The port the server will run on
ServerPort: 8080

# In case the port to the server is forwarded, specify the forwarded port
ForwardedPort: 443


[Directories]
# The directory the files created for instrumentation should be saved in
DataDirectory: your/path/InstrumentationServer/instrumentation-server-jobs

# Should the directory be deleted after instrumentation?
DeleteDataDirectory: true


[Android Jar]
# Path to android Jar
androidJarPath: your/path/android-sdk-linux/platforms/android-19/android.jar


[Keystore]
# The absolute path to the keystore
keyStorePath: your/path/Keystores/instrumentationKeystore

# The alias of the keystore
alias: instrumentationKeystore

# The pass of the keystore
storePass: your_password


[Fetch]
# Fetch APK metadata form F-Droid
fetchMetadata:  true

# The URL to the xml to fetch the metadata from
metadataXmlURL: https://f-droid.org/repo/index.xml

# Fetch APKs from F-Droid
fetchFdroidApks: true

TimeoutForApkFetchingInMinutes: 1
```
An example .ini file is included in the project root.

The tests for the server additionally need a config file at src/test/java/org/sentinel/instrumentationserver. You can, however, just adapt your normal config file to be similar to this example: 

```ini
[URL]
# The URL the server will run on.
ServerUrl: http://localhost


[Port]
# The port the server will run on
ServerPort: 8080

# In case the port to the server is forwarded, specify the forwarded port
ForwardedPort: 8080


[Security]
# Whether or not to enable HTTPS on the server.
# Needs to be turned off for the tests.
enableHTTPS: false

# The absolute path to the app signing keystore
keyStorePathSecurity: your/path/SecurityKeystore

# The password of the security keystore
storePassSecurity: security_password


[Directories]
# The directory the files created for instrumentation should be saved in
DataDirectory: InstrumentationServer/instrumentation-server-jobs

# Should the directory be deleted after instrumentation? Needs to be set to false in order for the tests to work.
DeleteDataDirectory: false


[Android Jar]
# Path to android Jar
androidJarPath: your/path/platforms/android-19/android.jar


[Keystore]
# The absolute path to the keystore
keyStorePath: your/path/keystores/mykeystore

# The alias of the keystore
alias: keystore-alias

# The pass of the keystore
storePass: keystore-password


[Fetch]
# Fetch APK metadata form F-Droid.
# Should be set to false for the tests as they would need a very long time to complete othwise.
fetchMetadata:  false

# The URL to the xml to fetch the metadata from
metadataXmlURL: https://f-droid.org/repo/index.xml

# Fetch APKs from F-Droid
fetchFdroidApks: false

TimeoutForApkFetchingInMinutes: 1
```

Lastly, run the following commands from your terminal:
```
This will generate all the model classes and endpoint interfaces defined in InstrumentationServer/raml/iaas.raml
mvn raml:generate

This will download all the maven dependencies and execute the tests.
mvn test

This command will run the server with the configuration specified in the config file "config.ini".
mvn exec:java
```

### The issues we faced:
 * The RAML-To-Java code from the code generator could have been better because the handling of multipart is a [bit cranky](https://github.com/mulesoft/raml-for-jax-rs/issues/105) and forced us to do hack fixes. We manually edited generated endpoint interfaces to use Jersey Multipart form-data features in the generated.workaround package. This requires merging the interfaces after changing the RAML file and generating the code with the generated interfaces.
 * A java web framework that offers a more high level means of development would probably have been a better choice for development of an instrumentation server alone. A combination of [Swagger](http://swagger.io/) and generated [Spring MVC Code](https://projects.spring.io/spring-framework/) is an interesting choice, for example and would have probably provided a higher ease and speed of development.
 * Every round of instrumentation seems to create a different byte array even though the input is the same. Testing was therefore a bit difficult since we could not test against a reference byte array in order to determine if the APK was instrumented correctly.

### How did we manage the instrumentation itself?

The [`Instrumentation-PEP`](https://github.com/lolobosse/DroidForce/tree/master/Instrumentation-PEP) project is our code base and we almost didn't change it, we made it bit a less verbose and solved some paths bugs to be able to package it in a (heavy) [runnable jar](https://github.com/mlin2/InstrumentationServer/blob/master/bit.jar) but we didn't change any logic of it.

We had an issue running it because of the fact that Java doesn't have a proper implementation of the [`chdir`](http://perldoc.perl.org/functions/chdir.html) (in Perl) or [`os.chdir()`](http://www.tutorialspoint.com/python/os_chdir.htm) (in Python) (see [there](http://stackoverflow.com/a/840229/2545832)). So we decided not to lose time trying to find a solution and moved to an old-plain bash script! (of course, Laurent's idea, who else can come up with a bash in 2016?).

In order to using new code for the Instrumentation, export the DroidForce Project at https://github.com/lolobosse/DroidForce2 as a standalone jar and replace DroidForce.jar the InstrumentationDependencies folder with your new jar. A better solution would be to get the direct java invocation with DroidForce to run with the creators of DroidForce.

Here is the 1970's style bash that saved our server:
```sh
#!/bin/bash

# This bash script runs the instrumentation because we could not get a call to the DroidForce project
# to run the instrumentation correctly.
# This bash script works because it runs the instrumentation in a process.

clear

echo The instrumentation service starts now

echo Be ready $USER !

# Go to InstrumentationDependencies directory to provide all dependencies for DroidForce.jar
cd InstrumentationDependencies

pwd

ls
# "m" as a suffix of the timeout argument tells timeout that the time is in minutes.
echo timeout ${13}m java -jar DroidForce.jar -sourceFile $1 -sinkFile $2 -taintWrapper $4 -apkFile $3 -o $5 -j -androidJar $6
/usr/bin/timeout ${13}m java -jar DroidForce.jar -sourceFile $1 -sinkFile $2 -taintWrapper $4 -apkFile $3 -o $5 -j -androidJar $6
# Check whether the last command was executed successfully and has returned status code 0 and only then execute
# the signing and aligning of the APK.
if [ $? == 0 ]; then

echo The APK gets now signed
# Sign the APK
jarsigner -verbose -keystore $8 -storepass ${10} -signedjar ${11} $7 $9

echo Previous signatures are now removed from the APK
#Delete previous signatures
zipalign -v 4 ${11} ${12}

fi
```

### Where is this server deployed?
As discussed with Enrico, the server is deployed on the server he gave us on port 443: [https://lapbroyg58.informatik.tu-muenchen.de:443](https://lapbroyg58.informatik.tu-muenchen.de:443).

### What are the other features of the server?

As you can see on the [RAML](http://raml.org/), there are other endpoints than the instrumentation of apps. We have to admit that the biggest and most interesting feature is the instrumentation but we also have *nice-to-have* features like:
 * HTTPS support which is an essential feature for the security of the server since it makes tempering with the APKs sent to the server and received from the server harder.
 * Fetching and storing of metadata from a remote XML file like the one F-Droid uses at https://f-droid.org/repo/index.xml. The metadata then gets associated with APKs as soon as they are instrumented by the background APK fetching or by sending an instrumentation request to the server directly.
 * Endpoints for a list of all metadata or metadata of instrumented APKs on the server.
 * Fetching and instrumenting of remote repository APKs in the background while also leaving the instrumentation service open to receive and handle requests. This has been tested with fetching APKs from F-Droid and trying to instrument them with a 1 minute timeout. 
 * A list of the apps that are already instrumented and available on the server to be downloaded.

### The "PlayStore" feature

We think that in order to have an interesting amount of testers, we need to already have an amount of apps which are instrumented so that the user can understand how precious and easy this instrumentation could be.

Therefore, we have instrumented many apps from the [FDroid Repository](https://f-droid.org/), an open source Android Application Market and we propose to the users to download them via our "Play Store Tab". All of these apps have been instrumented so they can actually be sure that these apps will respect their user policy.

![PlayStore](http://i.imgur.com/DZ6Tl8X.png)

### How does the server return the application? The instrumentation can take so much time!

Yes! That was an issue and we actually solved it using the simplest possible solution: from the app, we give the the ability to the user to check if the app is available for download (if the instrumentation has been successful) and if the server returns 200, we pull the app ; if the server returns something else, we do not mind and tell the user that the app is not ready yet

![Chart](http://i.imgur.com/X3NikMR.png)


Also to reduce the computation needed on the server, we hash the app and when it is the same, the app won't be re-instrumented. (You can see it on Pontus [scheme](#concretely-what-are-we-going-to-code))

### Limitations of the server
 * It is not checked whether the APK you receive corresponds to the one sent by the server. It could additionally be implemented to have the app check the hash of the APK with the server before installing it. 
 * Overall robustness: The backend for the service has been written by Sebastian alone and has not been thoroughly tested. Therefore while the basic use cases work with the Sentinel app and the server, other cases might not be handled well by the server. To tackle this issue, more people testing and developing the server would be needed.
 * It has an limited amount of RAM like every machine, so we suppose that sending it 1000's of apps is very likely to make it crash or lead to unexpected errors.
 * Due to a fatal error while fetching F-Droid APKs that is detected by the Java Runtime Environment that happens outside of the Java Virtual Machine in native code in the frame sqlite-3.8.11.2-3fc6f6da-4c38-4319-bac9-b596f7d5cbc6-libsqlitejdbc.so+0x64427, the server however crashes after a few hours. This may be solved by investigating the error. We used OpenJDK Runtime Environment (8.0_66-b17) and sqlite-jdbc 3.8.11.2 for running the server. After implementing more thread safe access to the database, this issue seems to be resolved.
 * After some time, the database seems to become unusable such that no APKs can be fetched anymore and also the sentinel app doesn't seem to be able to work with the server in that case. We do not know why this happens. It could be that a series of requests sent to the server puts the database in this state through the operations that are executed in the implementation or a bug in the implementation of the access to SQLite from java.
 * Currently the server fetches remote repository APKs in one single thread because we also want it to be able to handle instrumentation from the sentinel app at the same time. With a stronger server, it would be easy however to split up the list of links to APKs and let several threads instrument them. This may be done with a thread pool.
 * The database queries and Data Access Objects should be improved to handle more special cases with instrumentation data. [Hibernate](http://hibernate.org/) could be used to handle the database queries better than with Strings and prepared statements. For example, model classes for the database could be generated and queries could be written with methods instead of Strings. SQLite is probably not the best choice for an instrumentation server since it takes a long time (about three to five minutes) for the metadata fetching to be done because single transactions are written to the database file.
 * Because of time reasons and because only one person implemented all the features of the server, too few tests were written. 
 * Currently, only png logos are supported because they get returned on the endpoint with the .png extension. Some logo, out of this reason or another unknown reason, do not show up in the app store.
 * A big limitation is that only one version of an instrumented APK can currently be saved on the server. Subsequent requests for the same APK will not be instrumented and the first instrumentation of an APK corresponding to a hash will be returned. Also, some database accesses make usage of the "HASH" (SHA 512 hash) and "SHA256HASH" (SHA 256 hash) fields. They are therefore set to be UNIQUE. This can be changed by accessing by the ID and APKID fields in the tables APKS and METADATA, respectively, implementing the methods in the data access objects differently and removing the UNIQUE statements.
 * As the wrong resource interfaces were generated for form-data multiparts out of the RAML file, we introduced the workaround.resource package with the fixed resource interfaces.
 * The project both includes a jar of the DroidForce project and also a folder for the Instrumentation-PEPs files. We tried getting DroidForce running with a normal Java invocation however could not get it running. Possibly this is the case because of relative paths in the DroidForce implementation or because of concurrency problems.
 * When trying to use XML model classes to map the metadata from an XML file, Jersey only returns request failed for all requests. This is probably the case because JacksonFeature registers both the Json model classes and the XML model classes. Therefore, a manual mapping of the XML metadata was implemented. This may be improved by registering a custom ObjectMapper.

# What is still not working?

Unfortunately, we didn't manage to get the whole stack and ended with a major problem: the app starts the Decision Point as a Service and seems to be able to deploy policies properly but we have a big trouble, the apps which are being instrumented do not find the decision point even if we didn't change any name or reference compared to the original version ([appPDPj](https://github.com/secure-software-engineering/DroidForce/blob/master/appPDPj/src/de/tum/in/i22/uc/pdp/android/appPDP.java)).

We hope that we can solve this bug in few hours because it is the last step to a whole functioning product (from choosing your app to running it with the constraints of a policy).

Nevertheless, you can use the old appPDPj to deploy the policies and you will basically end up with the same result (you just need to install it).

## Conclusion
We had a lot of fun working at this project and we think this project shows the basic use cases of getting an APK instrumented or browsing an app store filled with instrumented apps. All of us put much effort into creating a nice interaction between the Sentinel app and the instrumentation server and we hope you will have fun trying it out. Also, if you are interested in this topic you are welcome to further develop and improve it.
Happy instrumenting!

Lolo, Pontus and Seb
