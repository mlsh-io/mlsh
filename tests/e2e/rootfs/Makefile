ROOTFS_DIR := $(CURDIR)
BUILDER_TAG := mlsh-e2e-builder:latest
OUTPUT_RAW := $(ROOTFS_DIR)/output/fedora-mlsh.raw

.PHONY: builder image clean

builder:
	podman build -t $(BUILDER_TAG) -f Containerfile.builder $(ROOTFS_DIR)

image: builder
	mkdir -p $(ROOTFS_DIR)/output
	podman run --rm --privileged \
		-v $(ROOTFS_DIR):/work:ro,Z \
		-v $(ROOTFS_DIR)/output:/work/output:Z \
		-v mlsh-e2e-mkosi:/var/lib/mkosi-work \
		$(BUILDER_TAG)
	@echo
	@echo "Image built: $(OUTPUT_RAW)"

clean:
	rm -rf $(ROOTFS_DIR)/output
