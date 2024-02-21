# instr package

not used

## build script

```xml
  <execution>
    <id>instrumentation</id>
    <phase>compile</phase>
    <goals>
      <goal>run</goal>
    </goals>
    <configuration>
      <skip>true</skip> <!-- see commons-instrumentation -->
      <target>
        <jar jarfile="${project.build.directory}/gi.jar"
             manifest="src/test/instrumentation/manifest.mf">
          <fileset dir="${project.build.testOutputDirectory}">
            <include name="instr/*.class" />
            <include name="Generic*.properties" />
            <include name="Properties*.properties" />
          </fileset>
          <zipfileset src="${org.javassist:javassist:jar}"
                      excludes="META-INF/**"/>
        </jar>
      </target>
    </configuration>
  </execution>
```

## TODO

 * back port to vavi-commons