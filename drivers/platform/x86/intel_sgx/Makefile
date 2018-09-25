#
# Intel SGX
#

obj-$(CONFIG_INTEL_SGX) += intel_sgx.o

ifdef CONFIG_NUMA
	intel_sgx-$(CONFIG_INTEL_SGX) += sgx_mempolicy.o
endif

intel_sgx-$(CONFIG_INTEL_SGX) += \
	sgx_ioctl.o \
	sgx_encl.o \
	sgx_encl_page.o \
	sgx_main.o \
	sgx_fault.o \
	sgx_vma.o \
