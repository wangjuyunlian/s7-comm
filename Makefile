test:
	cargo test

clean:
	cargo clean

.PHONY: rsync
rsync:
	rsync -av --exclude='target' ../s7-comm wjdev:/root/

