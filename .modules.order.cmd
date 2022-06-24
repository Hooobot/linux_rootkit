cmd_/home/grasshopper/ex3-lkm-hello/modules.order := {   echo /home/grasshopper/ex3-lkm-hello/rootkit.ko; :; } | awk '!x[$$0]++' - > /home/grasshopper/ex3-lkm-hello/modules.order
