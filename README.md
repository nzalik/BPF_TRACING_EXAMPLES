# BPF_TRACING_EXAMPLES
Some tracings script in python for tracing using eBPF

Currently, this project has two folders : DMA and General

# DMA folder

        The scripts written here are related to tracing functions related to Direcct Memory Access (DMA)

### Structure
    
    - dma_alloc_coherent_trace.c :  A C code that format data to return to event handle trace data
    - trace_dma_alloc_coherent.py : a script that attach dma_alloc_coherent_trace.c to event dma_alloc_coherent
    - trace_ioremap : a script to trace whn function ioremap is called in the kernel
    - trace_kmalloc : a script to trace when kmalloc funcion is called in the kernel
    - trace_mca_set_dma_io : a script to trace when mca_set_dma_io funcion is called in the kernel
    - trace_simple_DMA_Alloc : a script to trace when dma_alloc_coherent funcion is called in the kernel
    - trace_symple_DMA.py : a script to trace when request_dma funcion is called in the kernel

# General folder

        Inside this folder, the script are general scripts that ollow to trace syscall and others functions.