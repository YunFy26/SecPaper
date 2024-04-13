# ODDFuzzing

[ODDFuzz: Discovering Java Deserialization Vulnerabilities via Structure-Aware Directed Greybox Fuzzing](https://arxiv.org/abs/2304.04233)

# Concept

- ODD：Open Dynamic Deserialization
  
    The root cause of ODD vulnerabilities is that, the deserialized objects can reach (in terms of control flow) and affect (in terms of data flow) the sensitive code (sinks) of target applications.
    
    现有的发现ODD漏洞的工具：
    
    - GadgetInspectors
        - Static taint analysis
        - 静态分析有很大的局限性，由于运行时多态性，静态分析难以准确确定方法的调用路径
    - SerHybrid
        - 静态分析+动态分析
        - 在程序运行时跟踪对象在堆中的行为，然后生成注入对象进行fuzz，看是否能够到达sink
        - 生成的注入对象可能是无效的
- Gadget Chain
  
    Gadget chain：  Magic methods —> a security-sensitive call site.
    
    <aside>
    💡 Magic Methods(source)->Gadget->Runtime.exec(sink)
    
    </aside>
    
    ```java
    ObjectInputStream.readObject()
        PriorityQueue.readObject() 
            PriorityQueue.heapify()
                PriorityQueue.siftDown()
                    PriorityQueue.siftDownUsingComparator()
                        TransformingComparator.compare()
                            ChainedTransformer.transform()
    													ConstantTransformer.transform()
    														InvokerTransformer.transform()
    															Method.invoke()
    																Class.getMethod()
    														InvokerTransformer.transform()
    															Method.invoke()
    																Runtime.getRuntime()
    														InvokerTransformer.transform()
    															Method.invoke()
    																Runtime.exec()
    ```
    

# Design

![Untitled](https://github.com/YunFy26/SecPaper/blob/master/ODDFuzz/ODDFuzzing/Untitled.png)

> **Taint Analysis 污点分析**
> 
- Background
  
    However, due to the Java runtime polymorphism, virtual method invocations cannot be
    determined based on the declared types.
    
    由于Java运行时的多态性，虚拟方法调用不能根据声明的类型确定
    
    To solve this problem, we perform a lightweight summary-based taint analysis to identify suspicious gadget chains.
    
    为了解决这个问题，执行轻量级的基于摘要的污点分析
    
- Procedure
    - **Method Summary Computation  计算方法摘要**
      
        ODDFUZZ first computes static summaries for all methods on the classpath of the PUT
        that are later used for constructing gadget chains.
        
        首先计算PUT类路径上的所有方法的静态摘要，用于构建gadget chain（如方法的名称、参数类型、返回类型、访问修饰符等）
        
        对每个方法：
        
        ①提取所有参数和this作为方法摘要
        
        ②跟踪每个方法中变量的信息传播，主要关注Assign（赋值），Load（加载），Store（存储），Call（调用）
        
    - **Gadget Chain Identification  构建Gadget chain**
        - Magic Methods
          
            `readObject`, `hashCode`, `get`, `put`, `compare`, `readExternal`, `readResolve`, `finalize`, `equals`, `compareTo`, `toString`, `validateObject`, `readObjectNoData`, `<clinit>（类的静态初始化，static块中的代码）`, `call, doCall 通常与闭包和函数式编程相关，表示调用一个函数或闭包`
            
        - Security-Sensitive Call Sites   （Sink）
            - RCE
              
                `getDeclaredMethod`, `getConstructor`, `findClass`, `getMethod`, `loadClass`, `start`,
                `exec`, `invoke`, `forName`, `newInstance`, `exit`, `defineClass`, `call`, `invokeMethod`, `invokeStaticMethod`, `invokeConstructor`
                
                反射、类加载、命令执行
                
            - JNDI (Java 命名与目录接口)
              
                `getConnection`, `do_lookup`, `lookup`, `c_lookup`, `getObjectInstance`, `connect`
                
                > 命名Naming
                > 
                
                将Java对象以某个名称的形式绑定（binding）到一个容器环境（Context）中，以后调用容器环境（Context）的查找（lookup）方法又可以查找出某个名称所绑定的Java对象。
                
                容器环境（Context）本身也是一个Java对象，它也可以通过一个名称绑定到另一个容器环境（Context）
                
                > 目录Directory
                > 
                
                将一个对象的所有属性信息保存到一个容器环境中。<存储的是对象的属性>
                
            - SRA  (System Resource Access)
              
                `newBufferedReader`, `newBufferedWriter`, `delete`, `newInputStream`, 
                
                `newOutputStream`, `<init> （代表构造函数）`
                
                跟IO相关
                
            - SSRF
              
                `openConnection`, `openStream`
                
                跟URL相关
                
        
        ODDFUZZ performs a Depth-first-search (DFS) starting from this source gadget based on the method summaries to chain exploitable gadgets.
        
        一旦在类路径上发现Magic Method，那就以这个作为source，通过深度优先搜索方式，依据方法摘要信息构建gadget chain
        
        To avoid infinite loops (e.g.,recursive calls), we set a threshold for the maximum length
        of candidate gadget chain.
        
        为了避免死循环，为gadget chain设置了一个最大长度。
        
        Furthermore, to handle the runtime polymorphism of Java language, we perform Class Hierarchy Analysis (CHA) on the call statement only when the caller is tainted, avoiding the path explosion issue caused by blindly considering all available gadgets on the application’s classpath
        
        为了避免Java运行时多态性，仅在调用方被污染（tainted）时进行类层次分析，避免盲目考虑所有gadgets导致的路径爆炸问题。
        
        意思就是`comparator.compare()` 如果`comparator` 是不受信任的（tainted），那么所有重写的`compare()` 方法都会被列入候选gadget chain。
        
        其余情况，跟一般的基于调用图的污点分析工具一样。
        
        这种分析会在达到最大长度限制或到达Sink时停止。
        
        完成分析后，通过验证模块来确认gadget chain的有效性。
        

> **Structure-Aware Directed Greybox Fuzzing  结构化感知有向灰盒测试**
> 
- Fuzzing loop
  
    ![Untitled](https://github.com/YunFy26/SecPaper/blob/master/ODDFuzz/ODDFuzzing/Untitled%201.png)
    
    首先随机生成一个种子程序，然后对该程序进行变异，并执行变异后的程序。如果变异后的程序到达了漏洞点，则将该程序保存为新的种子程序，并重复该过程。否则，如果变异后的程序没有到达漏洞点，则将其丢弃，并重新生成一个新的种子程序。如此重复，直到找到一个到达漏洞点的程序，或者达到最大迭代次数。
    
    ```java
    import java.util.ArrayList;
    import java.util.List;
    
    public class GadgetChainFuzzer {
    
        private static final int MAX_ITERATIONS = 1000;
        private static final int MAX_DISTANCE = 100;
    
        public static void main(String[] args) {
            // 初始化种子程序
            List<Integer> seed = new ArrayList<>();
            seed.add(0);
    
            // 初始化最小距离
            int minDistance = Integer.MAX_VALUE;
    
            // 初始化gadget覆盖率
            Set<List<Integer>> gadgetCoverage = new HashSet<>();
    
            // 循环，直到找到一个到达漏洞点的程序，或者达到最大迭代次数
            for (int i = 0; i < MAX_ITERATIONS; i++) {
                // 选择一个种子程序
                List<Integer> s = selectSeed(seed);
    
                // 对种子程序进行变异
                List<Integer> sPrime = mutateSeed(s);
    
                // 执行变异后的程序
                boolean result = executeProgram(sPrime);
    
                // 如果变异后的程序到达了漏洞点
                if (result) {
                    // 将该程序保存为新的种子程序
                    seed = sPrime;
    
                    // 发送信号，表明漏洞点已被到达
                    emitSignal("Reachable");
                }
                // 如果变异后的程序没有到达漏洞点
                else {
                    // 计算变异后的程序与漏洞点的距离
                    int distance = computeDistance(sPrime);
    
                    // 如果距离小于最小距离
                    if (distance < minDistance) {
                        // 更新最小距离
                        minDistance = distance;
    
                        // 将该程序保存为新的种子程序
                        seed = sPrime;
                    }
    
                    // 如果变异后的程序没有到达漏洞点，并且没有覆盖任何新的gadget
                    if (!sPrime.coverage.containsAll(gadgetCoverage)) {
                        // 将该程序的gadget覆盖率添加到gadgetCoverage中
                        gadgetCoverage.addAll(sPrime.coverage);
                    }
                }
            }
        }
    
        private static List<Integer> selectSeed(List<Integer> seed) {
            // 从seed中随机选择一个程序
            return seed.get(new Random().nextInt(seed.size()));
        }
    
        private static List<Integer> mutateSeed(List<Integer> s) {
            // 对s进行变异
            List<Integer> sPrime = new ArrayList<>(s);
            sPrime.set(new Random().nextInt(s.size()), new Random().nextInt());
            return sPrime;
        }
    
        private static boolean executeProgram(List<Integer> s) {
            // 执行程序s
            // 如果程序到达漏洞点，则返回true，否则返回false
            return false;
        }
    
        private static int computeDistance(List<Integer> s) {
            // 计算程序s与漏洞点的距离
            // 距离可以通过跟踪程序执行过程中遇到的gadget来计算
            return 0;
        }
    
        private static void emitSignal(String signal) {
            // 发送信号，表明漏洞点已被到达
        }
    }
    ```
    
- Procedure
  
    **Structured Seed Generation  生成结构化种子**
    
    constructing a syntactically valid injection object requires
    
     1) devising its nested object hierarchy that reflects the execution flow of a given gadget chain
    
     2) assigning suitable property values to corresponding multilevel sub-objects to facilitate
    the injection object reaching the sensitive sink.
    
    构建一个在语法上有效的注入对象需要满足
    
    1）设计一个反映 gadget 链执行流的嵌套对象层次结构
    
    2）给多层次的子对象分配适当的属性值
    
    大量使用嵌套结构使得gadget chain fuzzing效率很低。于是采用 "property tree" 这种分层数据结构（根节点表示一个类对象，而叶节点表示类字段）设计了一种结构感知的种子生成方法。
    
    ![Untitled](https://github.com/YunFy26/SecPaper/blob/master/ODDFuzz/ODDFuzzing/Untitled%202.png)
    
    属性树构建过程
    
    ①实例化gadget chain中的每个类，利用反射动态收集每个类的可用属性构建属性树<图左边>
    
    - 当一个属性树的字段节点的类型表示（或继承）另一个属性树的根节点（一个类对象），则跟这个对象的属性树进行合并
    - 当一个属性树中的某个字段节点的类型是另一个属性树的根节点（一个类对象）实现的接口时，同样进行合并
    - 比如`PriorityQueue`类中的`Comparator` 字段的类型是`Comparator` 接口，`TransformingComparator` 类实现了`Comparator`接口，就可以把`TransformingComparator` 的属性树跟`PriorityQueue` 类的属性树进行合并
      
        ```java
        public class PriorityQueue<E> extends AbstractQueue<E>
            implements java.io.Serializable {
        ```
            private final Comparator<? super E> comparator;
            	```
            }
        
        public class TransformingComparator<I, O> implements Comparator<I>, Serializable {
            private static final long serialVersionUID = 3456940356043606220L;
            private final Comparator<O> decorated;
            private final Transformer<? super I, ? extends O> transformer;
        }
        ```
        
    
    ②We iteratively integrate the property tree based on the invocation order of the gadget chain until there are no more isolated but related sub-trees.
    
    按照gadget chain中的调用顺序整合属性树
    
    ③Then, the fuzzer starts traversing the backbone of this tree to
    convert it into an initial injection object for fuzzing
    
    开始遍历这棵树的主干，将其转换为用于模糊测试的初始注入对象<上图右边>没有子节点的节点设置为null以进行突变。（比如上图中的queue）
    
    **Seed Prioritization via Hybrid Feedback 通过混合反馈进行种子优先级排序** 
    
    the execution trace of an injection object is dynamically determined, which means that randomly generating and mutating an injection object leads to the sink-unawareness since the property layout of this nested injection object varies greatly in different fuzzing iterations.
    
    通过随机生成和变异注入对象，可能会导致属性布局的变化，使得测试在不同迭代中无法稳定地发现与接收器相关的问题。
    
    - 比如说
      
        ```java
        public class VulnerableClass {
            private boolean isVulnerable;
        
            public void processData() {
                if (isVulnerable) {
                    // Security-sensitive call site
                    // ...
                }
            }
        
            public void setVulnerability(boolean value) {
                isVulnerable = value;
            }
        }
        
        模糊测试器随机生成一个注入对象，该对象可能包含 VulnerableClass 的实例，
        并设置 isVulnerable 属性的值。
        
        在第一次迭代中，随机生成的注入对象可能导致 isVulnerable 为 true，
        从而触发了 processData 方法中的安全敏感调用位置。
        
        在第二次迭代中，由于注入对象的属性布局发生了变化，isVulnerable 的值可能是 false，
        导致模糊测试器生成的注入对象无法触发安全敏感调用位置。
        
        由于每次迭代中注入对象的属性布局不确定，模糊测试器可能会在不同的迭代中浪费时间，
        探索不同的路径，但无法持续引导测试目标到达安全敏感调用位置。
        这种无法感知目标执行路径的情况被描述为“sink-unawareness”.
        ```
        
    
    为了解决这个问题，使用**Hybrid Feedback**对种子进行优先级排序，有两个指标：
    
    - 种子距离（seed distance）
      
        种子 s 与安全敏感调用站点所在的目标基本块 Tb 之间的距离计算为
        
        ![Untitled](https://github.com/YunFy26/SecPaper/blob/master/ODDFuzz/ODDFuzzing/Untitled%203.png)
        
        **`d(s; Tb)`** 表示种子 **`s`** 到目标基本块 **`Tb`** 的距离。其中，**`db(m; Tb)`** 是种子 **`s`** 执行轨迹中基本块 **`m`** 到目标基本块 **`Tb`** 的距离。
        
    - gadget覆盖率（gadget coverage）
        1. 首先对生成的所有种子按照它们到目标的距离进行升序排序。
        2. 然后把排序后的种子按照优先级放入队列中，第一级是“favored queue”（优先队列），第二级是“less favored queue”（较不受优待的队列）。
        3. 优先队列（或具有相同距离但覆盖范围不同的种子）
    
    **Step-Forward Seed Mutation  种子前向突变**
    
    结合JQF（Java Quickcheck Fuzzing）框架，进行位级别的种子变异
    
    步骤如下
    
    - 遍历注入对象的属性树： 首先遍历要变异的属性树。
    - 检查每个属性的类型： 根据属性的类型，选择对应的变异方式。
        - 基本数据类型的变异： 使用JQF提供的伪随机方法，将未类型化的位参数转换为具有随机类型的值
        - 引用数据类型的变异： 对于引用数据类型，漏洞利用工具为特定类型定制了目标模板。例如，对于类类型的属性，工具会通过 **`random.choose()`** 方法随机选择该属性的候选类（即子类）。
        - 数组属性的变异： 对于数组类型的属性，漏洞利用工具使用 **`random.nextInt()`** 方法随机设置数组大小，并根据数组元素的类型（即继承数组类类型的实例）分配随机值。
        
        ![Untitled](https://github.com/YunFy26/SecPaper/blob/master/ODDFuzz/ODDFuzzing/Untitled%204.png)
        
    
    <Object类型的变异好像是从候选gadget chain中的对象或者方法中选取的>
    
    当遇到一个类对象的时候，会给一个标识字节，来确定是否改变它的属性值。
    
    - 基于Code Coverage的Fuzz    Coverage-guided Greybox Fuzzing
      
        ```java
        public class GadgetChain {
            private Comparator<Object> comparator;
        
            // Attacker-controllable method 1
            public void setComparator(Comparator<Object> comparator) {
                this.comparator = comparator;
            }
        
            // Attacker-controllable method 2
            public void processData() {
                if (comparator != null) {
                    comparator.compare(null, null);  // Security-sensitive call site
                }
            }
        }
        
        传统的代码覆盖率导向的模糊测试器生成一个注入对象，将 comparator 设置为 null，
        然后调用 processData 方法。这将触发 compare 方法，但由于 comparator 是 null，
        可能不会到达安全敏感的调用位置。
        
        由于新的代码片段（compare 方法）被触发，传统模糊测试器可能认为这是一个有趣的种子，
        并保留它用于下一轮模糊测试。然而，由于 comparator 是 null，实际上并没有到达漏洞链的目标
        ```
        
    - Directed Greybox Fuzzing    有向引导灰盒测试

